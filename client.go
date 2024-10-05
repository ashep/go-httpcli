package httpcli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"mime"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/rs/zerolog"
)

var DefaultUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
	"(KHTML, like Gecko) Chrome/86.0.4240.75 Safari/537.36"

type Client struct {
	id           string
	userAgents   []string
	proxyURLs    []string
	errorHandler ErrorHandler
	maxTries     int
	dumpDir      string

	c *http.Client
	l zerolog.Logger

	reqNum        int32
	handlingError bool
	mux           *sync.Mutex
}

// ErrorHandler is HTTP request error handler
type ErrorHandler func(ctx context.Context, c *Client, req *http.Request, rsp *http.Response, err error, tryN int) error

// New instantiates a client
func New(l zerolog.Logger) *Client {
	tr := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	c := http.Client{
		Transport: tr,
		Timeout:   60 * time.Second,
	}

	c.Jar, _ = cookiejar.New(&cookiejar.Options{})

	cli := &Client{
		id:         fmt.Sprintf("%d", time.Now().Unix()),
		userAgents: []string{DefaultUA},
		proxyURLs:  []string{},
		maxTries:   3,

		c: &c,
		l: l,

		mux: &sync.Mutex{},
	}

	cli.c.Transport.(*http.Transport).Proxy = func(request *http.Request) (*url.URL, error) {
		if len(cli.proxyURLs) != 0 {
			return url.Parse(cli.proxyURLs[rand.Intn(len(cli.proxyURLs))])
		}
		return nil, nil
	}

	return cli
}

func (c *Client) Client() *http.Client {
	return c.c
}

func (c *Client) SetUserAgents(ua []string) {
	c.userAgents = ua
}

func (c *Client) SetProxyURLs(urls []string) {
	c.proxyURLs = urls
}

func (c *Client) SetErrorHandler(fn ErrorHandler) {
	c.errorHandler = fn
}

func (c *Client) SetMaxTries(n int) {
	if n < 1 {
		n = 1
	}

	c.maxTries = n
}

func (c *Client) SetDumpDir(dir string) error {
	// Calculate dump directory
	dumpDir, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	dumpDir = filepath.Join(dumpDir, c.id)

	err = os.MkdirAll(dumpDir, 0700)
	if err != nil {
		return fmt.Errorf("failed to create dump directory: %w", err)
	}

	c.dumpDir = dumpDir
	c.l.Debug().Str("path", dumpDir).Msg("dump directory set")

	return nil
}

func (c *Client) Reset() error {
	j, err := cookiejar.New(nil)
	if err != nil {
		return fmt.Errorf("cookie jar new: %w", err)
	}

	c.c.Jar = j

	return nil
}

// DumpTransaction dumps an HTTP transaction content into a file
func (c *Client) DumpTransaction(
	req *http.Request,
	resp *http.Response,
	reqBody, respBody []byte,
	tryNum int,
) {
	// Create a dump file
	fPath := filepath.Join(c.dumpDir, fmt.Sprintf("%04d-%02d.txt", c.reqNum, tryNum))
	f, err := os.Create(fPath)
	if err != nil {
		c.l.Error().Err(err).Str("path", fPath).Msg("failed to create dump file")
		return
	}
	defer func() {
		_ = f.Close()
	}()

	// Dump method and URL
	if _, err := f.WriteString(fmt.Sprintf("%v %v\n\n", req.Method, req.URL)); err != nil {
		c.l.Error().Err(err).Str("path", fPath).Msg("failed to write to dump file")
		return
	}

	// Dump request headers
	for k, h := range req.Header {
		for _, v := range h {
			if _, err := f.Write([]byte(fmt.Sprintf("%v: %v\n", k, v))); err != nil {
				c.l.Error().Err(err).Str("path", fPath).Msg("failed to write to dump file")
				return
			}
		}
	}
	if _, err := f.WriteString("\n"); err != nil {
		c.l.Error().Err(err).Str("path", fPath).Msg("failed to write to dump file")
		return
	}

	// Dump request body
	if len(reqBody) > 0 {
		if _, err := f.Write(reqBody); err != nil {
			c.l.Error().Err(err).Str("path", fPath).Msg("failed to write to dump file")
			return
		}
	} else {
		if _, err := f.Write([]byte("EMPTY BODY")); err != nil {
			c.l.Error().Err(err).Str("path", fPath).Msg("failed to write to dump file")
			return
		}
	}
	if _, err := f.WriteString("\n"); err != nil {
		c.l.Error().Err(err).Str("path", fPath).Msg("failed to write to dump file")
		return
	}

	// DoRequest and response separator
	if _, err := f.WriteString("\n---\n\n"); err != nil {
		c.l.Error().Err(err).Str("path", fPath).Msg("failed to write to dump file")
		return
	}

	// Dump response headers
	for k, h := range resp.Header {
		for _, v := range h {
			if _, err := f.Write([]byte(fmt.Sprintf("%v: %v\n", k, v))); err != nil {
				c.l.Error().Err(err).Str("path", fPath).Msg("failed to write to dump file")
				return
			}
		}
	}
	if _, err := f.WriteString("\n"); err != nil {
		c.l.Error().Err(err).Str("path", fPath).Msg("failed to write to dump file")
		return
	}

	// Dump response body
	if len(respBody) > 0 {
		if _, err := f.Write(respBody); err != nil {
			c.l.Error().Err(err).Str("path", fPath).Msg("failed to write to dump file")
			return
		}
	} else {
		if _, err := f.Write([]byte("EMPTY BODY")); err != nil {
			c.l.Error().Err(err).Str("path", fPath).Msg("failed to write to dump file")
			return
		}
	}
}

func (c *Client) newRequest(ctx context.Context, method, u string, header http.Header, body []byte) (*http.Request, error) {
	if header == nil {
		header = http.Header{}
	}

	if header.Get("User-Agent") == "" {
		header.Set("User-Agent", c.userAgents[rand.Intn(len(c.userAgents))])
	}

	if header.Get("Accept") == "" {
		header.Set("Accept", "*/*")
	}

	if header.Get("Accept-Language") == "" {
		header.Set("Accept-Language", "en-US,en;q=0.9,ru;q=0.8,uk;q=0.7")
	}

	if header.Get("Cache-Control") == "" {
		header.Set("Cache-Control", "max-age=0")
	}

	req, err := http.NewRequestWithContext(ctx, method, u, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header = header

	return req, nil
}

// DoRequest performs an HTTP request
func (c *Client) DoRequest(
	ctx context.Context,
	method,
	u string,
	header http.Header,
	body []byte,
) (*http.Response, []byte, error) {
	var (
		err     error
		req     *http.Request
		res     *http.Response
		rspBody []byte
	)

	reqNum := atomic.LoadInt32(&c.reqNum)
	tryNum := 1
	for ; ; tryNum++ {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		default:
			// While handling error, it's allowed to work only to error handler, others must wait
			if c.handlingError {
				if _, ok := ctx.Value("errorHandler").(bool); !ok {
					c.l.Debug().Msg("waiting for client readiness")
					time.Sleep(time.Second)
					continue
				}
			}
		}

		reqNum = atomic.AddInt32(&c.reqNum, 1)

		req, err = c.newRequest(ctx, method, u, header.Clone(), body)
		if err != nil {
			return nil, nil, err
		}

		res, err = c.c.Do(req)
		if err == nil && res.StatusCode > 199 && res.StatusCode < 300 {
			break
		} else if err == nil {
			err = errors.New(res.Status)
		}

		c.l.Warn().
			Err(err).
			Int32("req_n", reqNum).
			Int("try_n", tryNum).
			Str("method", method).
			Str("url", u).
			Msg("failed to perform a request")

		if res != nil && c.dumpDir != "" {
			resBody, resErr := io.ReadAll(res.Body)
			if resErr == nil {
				c.DumpTransaction(req, res, body, resBody, tryNum)
			}
		}

		if res != nil {
			_ = res.Body.Close()
		}

		if c.errorHandler != nil {
			if c.handlingError {
				return nil, nil, fmt.Errorf("error is already being handled by another goroutine")
			}

			c.mux.Lock()
			c.handlingError = true
			hErr := c.errorHandler(context.WithValue(ctx, "errorHandler", true), c, req, res, err, tryNum)
			c.handlingError = false
			c.mux.Unlock()

			if hErr != nil {
				return nil, nil, fmt.Errorf("%w, %w", err, hErr)
			}
		}

		if tryNum == c.maxTries || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, nil, err
		}

		time.Sleep(time.Second * time.Duration(tryNum))
	}

	c.l.Debug().
		Int32("req_n", reqNum).
		Int("try_n", tryNum).
		Str("method", method).
		Str("url", u).
		Str("status", res.Status).
		Msg("request ok")

	defer func() {
		_ = res.Body.Close()
	}()
	if rspBody, err = io.ReadAll(res.Body); err != nil {
		return res, nil, fmt.Errorf("failed to read response body: %v", err)
	}

	if c.dumpDir != "" {
		c.DumpTransaction(req, res, body, rspBody, tryNum)
	}

	// Check response status
	if res.StatusCode >= 400 {
		return res, rspBody, fmt.Errorf("HTTP response status: %v", res.Status)
	}

	return res, rspBody, err
}

// Get perform a GET request
func (c *Client) Get(ctx context.Context, u string, args url.Values, header http.Header) ([]byte, error) {
	if args != nil {
		u = CombineURL(u, "", args)
	}

	_, body, err := c.DoRequest(ctx, "GET", u, header, []byte(""))
	return body, err
}

// GetQueryDoc performs a GET request and transform response into a goquery document
func (c *Client) GetQueryDoc(ctx context.Context, u string, args url.Values, header http.Header) (*goquery.Document, error) {
	body, err := c.Get(ctx, u, args, header)
	if err != nil {
		return nil, err
	}

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	return doc, nil
}

// GetJSON performs a GET HTTP request and parses the response into a JSON
func (c *Client) GetJSON(ctx context.Context, u string, args url.Values, header http.Header, target interface{}) error {
	if header == nil {
		header = http.Header{}
	}
	if header.Get("X-Requested-With") == "" {
		header.Set("X-Requested-With", "XMLHttpRequest")
	}

	body, err := c.Get(ctx, u, args, header)
	if err != nil {
		return err
	}

	return json.Unmarshal(body, target)
}

// GetFile gets a file and stores it on the disk.
//
// If fPath doesn't contain an extension, it will be added automatically.
// In case of success file extension returned
func (c *Client) GetFile(ctx context.Context, u string, args url.Values, header http.Header, fPath string) (string, error) {
	fExt := ""

	if args != nil {
		u = CombineURL(u, "", args)
	}

	resp, body, err := c.DoRequest(ctx, "GET", u, header, nil)
	if err != nil {
		return "", err
	}

	// Calculate file extension
	if !filepath.IsAbs(fPath) {
		if fPath, err = filepath.Abs(fPath); err != nil {
			return "", err
		}
	}
	if !regexp.MustCompile(`\.[a-zA-Z0-9]+$`).Match([]byte(fPath)) {
		cType := resp.Header.Get("Content-Type")
		cType = strings.ReplaceAll(cType, "/jpg", "/jpeg")

		fExtArr, err := mime.ExtensionsByType(cType)
		if err != nil || len(fExtArr) == 0 {
			return "", fmt.Errorf("failed to determine file extension for content type %q: %v", cType, err)
		}
		fExt = fExtArr[len(fExtArr)-1]
		fPath += fExt
	}

	// Write file to disk
	f, err := os.Create(fPath)
	if err != nil {
		return "", fmt.Errorf("failed to open file %v: %v", fPath, err)
	}
	defer func() {
		_ = f.Close()
	}()

	if _, err := f.Write(body); err != nil {
		return "", fmt.Errorf("failed to write to file %v: %v", fPath, err)
	}

	return fExt, nil
}

// Post performs a POST request
func (c *Client) Post(ctx context.Context, u string, header http.Header, body []byte) ([]byte, error) {
	if header == nil {
		header = http.Header{}
	}

	_, rBody, err := c.DoRequest(ctx, "POST", u, header, body)
	return rBody, err
}

// PostForm posts a form
func (c *Client) PostForm(ctx context.Context, u string, args url.Values, header http.Header) ([]byte, error) {
	if header == nil {
		header = http.Header{}
	}

	header.Add("Content-Type", "application/x-www-form-urlencoded")

	return c.Post(ctx, u, header, []byte(args.Encode()))
}

// PostJSON posts a JSON request
func (c *Client) PostJSON(ctx context.Context, u string, header http.Header, data interface{}) ([]byte, error) {
	if header == nil {
		header = http.Header{}
	}

	header.Add("Content-Type", "application/json")

	dataB, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	return c.Post(ctx, u, header, dataB)
}

// PostFormParseJSON performs a POST request and parses JSON response
func (c *Client) PostFormParseJSON(ctx context.Context, u string, args url.Values, header http.Header, target interface{}) error {
	if header == nil {
		header = http.Header{}
	}

	resp, err := c.PostForm(ctx, u, args, header)
	if err != nil {
		return err
	}

	return json.Unmarshal(resp, target)
}

// PostJSONParseJSON performs a POST request having JSON body and parses JSON response
func (c *Client) PostJSONParseJSON(ctx context.Context, u string, data interface{}, header http.Header, target interface{}) error {
	if header == nil {
		header = http.Header{}
	}

	if header.Get("Content-Type") == "" {
		header.Add("Content-Type", "application/json")
	}

	resp, err := c.PostJSON(ctx, u, header, data)
	if err != nil {
		return err
	}

	return json.Unmarshal(resp, target)
}

// GetExtIPAddrInfo returns information about client's external IP address
func (c *Client) GetExtIPAddrInfo(ctx context.Context) (string, error) {
	var (
		b   []byte
		r   string
		err error
	)

	if b, err = c.Get(ctx, "https://ifconfig.io/ip", nil, nil); err != nil {
		return r, err
	}
	r += fmt.Sprintf("address: %s", b)

	if b, err = c.Get(ctx, "https://ifconfig.io/country_code", nil, nil); err != nil {
		return r, err
	}
	r = fmt.Sprintf("%v, region: %s", r, b)

	return strings.ReplaceAll(r, "\n", ""), nil
}

// CombineURL combines two URLs
func CombineURL(a string, b string, args url.Values) string {
	aURL, err := url.Parse(a)
	if err != nil {
		return ""
	}

	if b != "" {
		bURL, err := url.Parse(b)
		if err != nil {
			return ""
		}

		aURL.Path += bURL.Path
		aURL.Path = strings.ReplaceAll(aURL.Path, "//", "/")
	}

	if args != nil {
		q := aURL.Query()
		for k, v := range args {
			for _, sv := range v {
				q.Add(k, sv)
			}
		}

		aURL.RawQuery = q.Encode()
	}

	return aURL.String()
}
