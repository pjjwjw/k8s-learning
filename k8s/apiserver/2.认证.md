[kubeAPIServer, err := CreateKubeAPIServer(kubeAPIServerConfig, apiExtensionsServer.GenericAPIServer)](https://github.com/pjjwjw/kubernetes/blob/88c6ea125f001c612b800d028d7ccfe908aa5082/cmd/kube-apiserver/app/server.go#L207)

[kubeAPIServer, err := kubeAPIServerConfig.Complete().New(delegateAPIServer)](https://github.com/pjjwjw/kubernetes/blob/88c6ea125f001c612b800d028d7ccfe908aa5082/cmd/kube-apiserver/app/server.go#L228)

[s, err := c.GenericConfig.New("kube-apiserver", delegationTarget)](https://github.com/pjjwjw/kubernetes/blob/d2abddd9096e30a6c47c72e3e43a033e99c1c149/pkg/controlplane/instance.go#L349)

[New](https://github.com/pjjwjw/kubernetes/blob/b604a6669b439205d3425749530620ff903312dd/vendor/k8s.io/apiserver/pkg/server/config.go#L567)

```golang
handlerChainBuilder := func(handler http.Handler) http.Handler {
    return c.BuildHandlerChainFunc(handler, c.Config)
}
apiServerHandler := NewAPIServerHandler(name, c.Serializer, handlerChainBuilder, delegationTarget.UnprotectedHandler())
s := &GenericAPIServer{
    ...
    Handler: apiServerHandler,
    ...
}

// APIServerHandlers holds the different http.Handlers used by the API server.
// This includes the full handler chain, the director (which chooses between gorestful and nonGoRestful,
// the gorestful handler (used for the API) which falls through to the nonGoRestful handler on unregistered paths,
// and the nonGoRestful handler (which can contain a fallthrough of its own)
// FullHandlerChain -> Director -> {GoRestfulContainer,NonGoRestfulMux} based on inspection of registered web services
type APIServerHandler struct
	// FullHandlerChain is the one that is eventually served with.  It should include the full filter
	// chain and then call the Director.
	FullHandlerChain http.Handler
	// The registered APIs.  InstallAPIs uses this.  Other servers probably shouldn't access this directly.
	GoRestfulContainer *restful.Container
	// NonGoRestfulMux is the final HTTP handler in the chain.
	// It comes after all filters and the API handling
	// This is where other servers can attach handler to various parts of the chain.
	NonGoRestfulMux *mux.PathRecorderMux

	// Director is here so that we can properly handle fall through and proxy cases.
	// This looks a bit bonkers, but here's what's happening.  We need to have /apis handling registered in gorestful in order to have
	// swagger generated for compatibility.  Doing that with `/apis` as a webservice, means that it forcibly 404s (no defaulting allowed)
	// all requests which are not /apis or /apis/.  We need those calls to fall through behind goresful for proper delegation.  Trying to
	// register for a pattern which includes everything behind it doesn't work because gorestful negotiates for verbs and content encoding
	// and all those things go crazy when gorestful really just needs to pass through.  In addition, openapi enforces unique verb constraints
	// which we don't fit into and it still muddies up swagger.  Trying to switch the webservices into a route doesn't work because the
	//  containing webservice faces all the same problems listed above.
	// This leads to the crazy thing done here.  Our mux does what we need, so we'll place it in front of gorestful.  It will introspect to
	// decide if the route is likely to be handled by goresful and route there if needed.  Otherwise, it goes to PostGoRestful mux in
	// order to handle "normal" paths and delegation. Hopefully no API consumers will ever have to deal with this level of detail.  I think
	// we should consider completely removing gorestful.
	// Other servers should only use this opaquely to delegate to an API server.
	Director http.Handler
}
```

c.BuildHandlerChainFunc初始化:
[BuildHandlerChainFunc: DefaultBuildHandlerChain](https://github.com/pjjwjw/kubernetes/blob/b604a6669b439205d3425749530620ff903312dd/vendor/k8s.io/apiserver/pkg/server/config.go#L331)

[handler = genericapifilters.WithAuthentication(handler, c.Authentication.Authenticator, failedHandler, c.Authentication.APIAudiences)](https://github.com/pjjwjw/kubernetes/blob/b604a6669b439205d3425749530620ff903312dd/vendor/k8s.io/apiserver/pkg/server/config.go#L792)


[withAuthentication](https://github.com/pjjwjw/kubernetes/blob/b604a6669b439205d3425749530620ff903312dd/vendor/k8s.io/apiserver/pkg/endpoints/filters/authentication.go#L45)
``` golang
func withAuthentication(handler http.Handler, auth authenticator.Request, failed http.Handler, apiAuds authenticator.Audiences, metrics recordMetrics) http.Handler {
    if auth == nil {
        klog.Warning("Authentication is disabled")
        return handler
    }
    // 这里为了便于理解把源码做了修改
    f := func(w http.ResponseWriter, req *http.Request) {
        authenticationStart := time.Now()

        if len(apiAuds) > 0 {
            req = req.WithContext(authenticator.WithAudiences(req.Context(), apiAuds))
        }
        resp, ok, err := auth.AuthenticateRequest(req)
        // auth等于c.Authentication.Authenticator, 赋值的位置为:
        // https://github.com/kubernetes/kubernetes/blob/34b0fcef5fc47e3fcddf7f6ca1b3e6176b2a5323/pkg/kubeapiserver/authenticator/config.go#L213
        // authenticator := union.New(authenticators...)
        authenticationFinish := time.Now()
        defer func() {
            metrics(req.Context(), resp, ok, err, apiAuds, authenticationStart, authenticationFinish)
        }()
        if err != nil || !ok {
            if err != nil {
                klog.ErrorS(err, "Unable to authenticate the request")
            }
            failed.ServeHTTP(w, req)
            return
        }

        if !audiencesAreAcceptable(apiAuds, resp.Audiences) {
            err = fmt.Errorf("unable to match the audience: %v , accepted: %v", resp.Audiences, apiAuds)
            klog.Error(err)
            failed.ServeHTTP(w, req)
            return
        }

        // authorization header is not required anymore in case of a successful authentication.
        req.Header.Del("Authorization")

        req = req.WithContext(genericapirequest.WithUser(req.Context(), resp.User))
        handler.ServeHTTP(w, req)
    }
    // f是func(ResponseWriter, *Request)类型, http.HandlerFunc(f)将f转换成了HandlerFunc, 该类型实现了Handler接口
    // 假设handler:=withAuthentication(...), 那么调用handler.ServeHTTP(w, r)等价于调用f(w, r)
    // 正常情况会调用handler.ServeHTTP(w, req), 异常情况会调用failed.ServeHTTP(w, req)
    return http.HandlerFunc(f)
}

// HandlerFunc定义:
// The HandlerFunc type is an adapter to allow the use of
// ordinary functions as HTTP handlers. If f is a function
// with the appropriate signature, HandlerFunc(f) is a
// Handler that calls f.
type HandlerFunc func(ResponseWriter, *Request)

// ServeHTTP calls f(w, r).
func (f HandlerFunc) ServeHTTP(w ResponseWriter, r *Request) {
    f(w, r)
}

// handle 定义
// A Handler responds to an HTTP request.
//
// ServeHTTP should write reply headers and data to the ResponseWriter
// and then return. 
type Handler interface {
    ServeHTTP(ResponseWriter, *Request)
}
```
