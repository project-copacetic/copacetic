"use strict";(self.webpackChunkwebsite=self.webpackChunkwebsite||[]).push([[6436],{256:(e,n,t)=>{t.r(n),t.d(n,{assets:()=>s,contentTitle:()=>d,default:()=>u,frontMatter:()=>c,metadata:()=>r,toc:()=>l});var i=t(4848),o=t(8453);const c={title:"Custom buildkit addresses"},d=void 0,r={id:"custom-address",title:"Custom buildkit addresses",description:"You may need to specify a custom address using the --addr flag. Here are the supported formats:",source:"@site/versioned_docs/version-v0.7.x/custom-address.md",sourceDirName:".",slug:"/custom-address",permalink:"/copacetic/website/custom-address",draft:!1,unlisted:!1,tags:[],version:"v0.7.x",frontMatter:{title:"Custom buildkit addresses"},sidebar:"sidebar",previous:{title:"Github Action",permalink:"/copacetic/website/github-action"},next:{title:"Output",permalink:"/copacetic/website/output"}},s={},l=[{value:"Buildkit Connection Examples",id:"buildkit-connection-examples",level:2},{value:"Option 1: Connect using defaults",id:"option-1-connect-using-defaults",level:3},{value:"Option 2: Connect to buildx",id:"option-2-connect-to-buildx",level:3},{value:"Option 3: Buildkit in a container",id:"option-3-buildkit-in-a-container",level:3},{value:"Option 4: Buildkit over TCP",id:"option-4-buildkit-over-tcp",level:3},{value:"Option 5: Buildkit over TCP with mTLS",id:"option-5-buildkit-over-tcp-with-mtls",level:3}];function a(e){const n={code:"code",em:"em",h2:"h2",h3:"h3",li:"li",p:"p",pre:"pre",ul:"ul",...(0,o.R)(),...e.components};return(0,i.jsxs)(i.Fragment,{children:[(0,i.jsxs)(n.p,{children:["You may need to specify a custom address using the ",(0,i.jsx)(n.code,{children:"--addr"})," flag. Here are the supported formats:"]}),"\n",(0,i.jsxs)(n.ul,{children:["\n",(0,i.jsxs)(n.li,{children:[(0,i.jsx)(n.code,{children:"unix:///path/to/buildkit.sock"})," - Connect to buildkit over unix socket."]}),"\n",(0,i.jsxs)(n.li,{children:[(0,i.jsx)(n.code,{children:"tcp://$BUILDKIT_ADDR:$PORT"})," - Connect to buildkit over TCP. (not recommended for security reasons)"]}),"\n",(0,i.jsxs)(n.li,{children:[(0,i.jsx)(n.code,{children:"docker://<docker connection spec>"})," - Connect to docker, currently only unix sockets are supported, e.g. ",(0,i.jsx)(n.code,{children:"docker://unix:///var/run/docker.sock"})," (or just ",(0,i.jsx)(n.code,{children:"docker://"}),")."]}),"\n",(0,i.jsxs)(n.li,{children:[(0,i.jsx)(n.code,{children:"docker-container://my-buildkit-container"})," - Connect to a buildkitd running in a docker container."]}),"\n",(0,i.jsxs)(n.li,{children:[(0,i.jsx)(n.code,{children:"buildx://my-builder"})," - Connect to a buildx builder (or ",(0,i.jsx)(n.code,{children:"buildx://"})," for the currently selected builder). ",(0,i.jsx)(n.em,{children:"Note: only container-backed buildx instances are currently supported"})]}),"\n",(0,i.jsxs)(n.li,{children:[(0,i.jsx)(n.code,{children:"nerdctl-container://my-container-name"})," - Similar to ",(0,i.jsx)(n.code,{children:"docker-container"})," but uses ",(0,i.jsx)(n.code,{children:"nerdctl"}),"."]}),"\n",(0,i.jsxs)(n.li,{children:[(0,i.jsx)(n.code,{children:"podman-container://my-container-name"})," - Similar to ",(0,i.jsx)(n.code,{children:"docker-container"})," but uses ",(0,i.jsx)(n.code,{children:"podman"}),"."]}),"\n",(0,i.jsxs)(n.li,{children:[(0,i.jsx)(n.code,{children:"ssh://myhost"})," - Connect to a buildkit instance over SSH. Format of the host spec should mimic the SSH command."]}),"\n",(0,i.jsxs)(n.li,{children:[(0,i.jsx)(n.code,{children:"kubepod://mypod"})," - Connect to buildkit running in a Kubernetes pod. Can also specify kubectl context and pod namespace (",(0,i.jsx)(n.code,{children:"kubepod://mypod?context=foo&namespace=notdefault"}),")."]}),"\n"]}),"\n",(0,i.jsx)(n.h2,{id:"buildkit-connection-examples",children:"Buildkit Connection Examples"}),"\n",(0,i.jsx)(n.h3,{id:"option-1-connect-using-defaults",children:"Option 1: Connect using defaults"}),"\n",(0,i.jsx)(n.pre,{children:(0,i.jsx)(n.code,{className:"language-bash",children:"copa patch -i docker.io/library/nginx:1.21.6 -r nginx.1.21.6.json -t 1.21.6-patched\n"})}),"\n",(0,i.jsx)(n.h3,{id:"option-2-connect-to-buildx",children:"Option 2: Connect to buildx"}),"\n",(0,i.jsx)(n.pre,{children:(0,i.jsx)(n.code,{className:"language-bash",children:"docker buildx create --name demo\ncopa patch -i docker.io/library/nginx:1.21.6 -r nginx.1.21.6.json -t 1.21.6-patched --addr buildx://demo\n"})}),"\n",(0,i.jsx)(n.h3,{id:"option-3-buildkit-in-a-container",children:"Option 3: Buildkit in a container"}),"\n",(0,i.jsx)(n.pre,{children:(0,i.jsx)(n.code,{className:"language-bash",children:'export BUILDKIT_VERSION=v0.12.4\ndocker run \\\n    --detach \\\n    --rm \\\n    --privileged \\\n    --name buildkitd \\\n    --entrypoint buildkitd \\\n    "moby/buildkit:$BUILDKIT_VERSION"\n\ncopa patch -i docker.io/library/nginx:1.21.6 -r nginx.1.21.6.json -t 1.21.6-patched --addr docker-container://buildkitd\n'})}),"\n",(0,i.jsx)(n.h3,{id:"option-4-buildkit-over-tcp",children:"Option 4: Buildkit over TCP"}),"\n",(0,i.jsx)(n.pre,{children:(0,i.jsx)(n.code,{className:"language-bash",children:'export BUILDKIT_VERSION=v0.12.4\nexport BUILDKIT_PORT=8888\ndocker run \\\n    --detach \\\n    --rm \\\n    --privileged \\\n    -p 127.0.0.1:$BUILDKIT_PORT:$BUILDKIT_PORT/tcp \\\n    --name buildkitd \\\n    --entrypoint buildkitd \\\n    "moby/buildkit:$BUILDKIT_VERSION" \\\n    --addr tcp://0.0.0.0:$BUILDKIT_PORT\n\ncopa patch \\\n    -i docker.io/library/nginx:1.21.6 \\\n    -r nginx.1.21.6.json \\\n    -t 1.21.6-patched \\\n    -a tcp://0.0.0.0:$BUILDKIT_PORT\n'})}),"\n",(0,i.jsx)(n.h3,{id:"option-5-buildkit-over-tcp-with-mtls",children:"Option 5: Buildkit over TCP with mTLS"}),"\n",(0,i.jsx)(n.pre,{children:(0,i.jsx)(n.code,{className:"language-bash",children:'export BUILDKIT_VERSION=v0.12.4\nexport BUILDKIT_PORT=8888\ndocker run \\\n    --detach \\\n    --rm \\\n    --privileged \\\n    -p 127.0.0.1:$BUILDKIT_PORT:$BUILDKIT_PORT/tcp \\\n    --name buildkitd \\\n    --entrypoint buildkitd \\\n    -v $PWD/.certs:/etc/buildkit/certs \\\n    "moby/buildkit:$BUILDKIT_VERSION" \\\n    --addr tcp://0.0.0.0:$BUILDKIT_PORT \\\n    --tlscacert /etc/buildkit/certs/daemon/ca.pem \\\n    --tlscert /etc/buildkit/certs/daemon/cert.pem \\\n    --tlskey /etc/buildkit/certs/daemon/key.pem\n\ncopa patch \\\n    -i docker.io/library/nginx:1.21.6 \\\n    -r nginx.1.21.6.json \\\n    -t 1.21.6-patched \\\n    -a tcp://0.0.0.0:$BUILDKIT_PORT\n    --cacert /path/to/ca-certificate \\\n    --cert  /path/to/buildkit/client/cert \\\n    --key /path/to/buildkit/key\n'})})]})}function u(e={}){const{wrapper:n}={...(0,o.R)(),...e.components};return n?(0,i.jsx)(n,{...e,children:(0,i.jsx)(a,{...e})}):a(e)}},8453:(e,n,t)=>{t.d(n,{R:()=>d,x:()=>r});var i=t(6540);const o={},c=i.createContext(o);function d(e){const n=i.useContext(c);return i.useMemo((function(){return"function"==typeof e?e(n):{...n,...e}}),[n,e])}function r(e){let n;return n=e.disableParentContext?"function"==typeof e.components?e.components(o):e.components||o:d(e.components),i.createElement(c.Provider,{value:n},e.children)}}}]);