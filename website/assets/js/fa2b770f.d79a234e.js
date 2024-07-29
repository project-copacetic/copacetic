"use strict";(self.webpackChunkwebsite=self.webpackChunkwebsite||[]).push([[5368],{7570:(e,i,a)=>{a.r(i),a.d(i,{assets:()=>r,contentTitle:()=>c,default:()=>d,frontMatter:()=>o,metadata:()=>s,toc:()=>l});var n=a(4848),t=a(8453);const o={title:"FAQ"},c=void 0,s={id:"faq",title:"FAQ",description:"What kind of vulnerabilities can Copa patch?",source:"@site/versioned_docs/version-v0.5.x/faq.md",sourceDirName:".",slug:"/faq",permalink:"/copacetic/website/v0.5.x/faq",draft:!1,unlisted:!1,tags:[],version:"v0.5.x",frontMatter:{title:"FAQ"},sidebar:"sidebar",previous:{title:"Design",permalink:"/copacetic/website/v0.5.x/design"},next:{title:"Scanner Plugins",permalink:"/copacetic/website/v0.5.x/scanner-plugins"}},r={},l=[{value:"What kind of vulnerabilities can Copa patch?",id:"what-kind-of-vulnerabilities-can-copa-patch",level:2},{value:"What kind of vulnerabilities can Copa not patch?",id:"what-kind-of-vulnerabilities-can-copa-not-patch",level:2},{value:"Can I replace the package repositories in the image with my own?",id:"can-i-replace-the-package-repositories-in-the-image-with-my-own",level:2}];function p(e){const i={a:"a",admonition:"admonition",blockquote:"blockquote",code:"code",h2:"h2",p:"p",pre:"pre",...(0,t.R)(),...e.components};return(0,n.jsxs)(n.Fragment,{children:[(0,n.jsx)(i.h2,{id:"what-kind-of-vulnerabilities-can-copa-patch",children:"What kind of vulnerabilities can Copa patch?"}),"\n",(0,n.jsxs)(i.p,{children:['Copa is capable of patching "OS level" vulnerabilities. This includes packages (like ',(0,n.jsx)(i.code,{children:"openssl"}),") in the image that are managed by a package manager such as ",(0,n.jsx)(i.code,{children:"apt"})," or ",(0,n.jsx)(i.code,{children:"yum"}),'. Copa is not currently capable of patching vulnerabilities at the "application level" such as Python packages or Go modules (see ',(0,n.jsx)(i.a,{href:"#what-kind-of-vulnerabilities-can-copa-not-patch",children:"below"})," for more details)."]}),"\n",(0,n.jsx)(i.h2,{id:"what-kind-of-vulnerabilities-can-copa-not-patch",children:"What kind of vulnerabilities can Copa not patch?"}),"\n",(0,n.jsxs)(i.p,{children:['Copa is not capable of patching vulnerabilities for compiled languages, like Go, at the "application level", for instance, Go modules. If your application uses a vulnerable version of the ',(0,n.jsx)(i.code,{children:"golang.org/x/net"})," module, Copa will be unable to patch it. This is because Copa doesn't have access to the application's source code or the knowledge of how to build it, such as compiler flags, preventing it from patching vulnerabilities at the application level."]}),"\n",(0,n.jsxs)(i.p,{children:["To patch vulnerabilities for applications, you can package these applications and consume them from package repositories, like ",(0,n.jsx)(i.code,{children:"http://archive.ubuntu.com/ubuntu/"})," for Ubuntu, and ensure Trivy can scan and report vulnerabilities for these packages. This way, Copa can patch the applications as a whole, though it cannot patch specific modules within the applications."]}),"\n",(0,n.jsx)(i.h2,{id:"can-i-replace-the-package-repositories-in-the-image-with-my-own",children:"Can I replace the package repositories in the image with my own?"}),"\n",(0,n.jsx)(i.admonition,{type:"caution",children:(0,n.jsx)(i.p,{children:"Experimental: This feature might change without preserving backwards compatibility."})}),"\n",(0,n.jsxs)(i.p,{children:["Copa does not support replacing the repositories in the package managers with alternatives. Images must already use the intended package repositories. For example, for debian, updating ",(0,n.jsx)(i.code,{children:"/etc/apt/sources.list"})," from ",(0,n.jsx)(i.code,{children:"http://archive.ubuntu.com/ubuntu/"})," to a mirror, such as ",(0,n.jsx)(i.code,{children:"https://mirrors.wikimedia.org/ubuntu/"}),"."]}),"\n",(0,n.jsxs)(i.p,{children:["If you need the tooling image to use a different package repository, you can create a source policy to define a replacement image and/or pin to a digest. For example, the following source policy replaces ",(0,n.jsx)(i.code,{children:"docker.io/library/debian:11-slim"})," image with ",(0,n.jsx)(i.code,{children:"foo.io/bar/baz:latest@sha256:42d3e6bc186572245aded5a0be381012adba6d89355fa9486dd81b0c634695b5"}),":"]}),"\n",(0,n.jsx)(i.pre,{children:(0,n.jsx)(i.code,{className:"language-shell",children:'cat <<EOF > source-policy.json\n{\n    "rules": [\n        {\n            "action": "CONVERT",\n            "selector": {\n                "identifier": "docker-image://docker.io/library/debian:11-slim"\n            },\n            "updates": {\n                "identifier": "docker-image://foo.io/bar/baz:latest@sha256:42d3e6bc186572245aded5a0be381012adba6d89355fa9486dd81b0c634695b5"\n            }\n        }\n    ]\n}\nEOF\n\nexport EXPERIMENTAL_BUILDKIT_SOURCE_POLICY=source-policy.json\n'})}),"\n",(0,n.jsxs)(i.blockquote,{children:["\n",(0,n.jsxs)(i.p,{children:["Tooling image for Debian-based images are ",(0,n.jsx)(i.code,{children:"docker.io/library/debian:11-slim"})," and RPM-based repos are ",(0,n.jsx)(i.code,{children:"mcr.microsoft.com/cbl-mariner/base/core:2.0"}),"."]}),"\n"]}),"\n",(0,n.jsxs)(i.p,{children:["For more information on source policies, see ",(0,n.jsx)(i.a,{href:"https://docs.docker.com/build/building/env-vars/#experimental_buildkit_source_policy",children:"Buildkit Source Policies"}),"."]})]})}function d(e={}){const{wrapper:i}={...(0,t.R)(),...e.components};return i?(0,n.jsx)(i,{...e,children:(0,n.jsx)(p,{...e})}):p(e)}},8453:(e,i,a)=>{a.d(i,{R:()=>c,x:()=>s});var n=a(6540);const t={},o=n.createContext(t);function c(e){const i=n.useContext(o);return n.useMemo((function(){return"function"==typeof e?e(i):{...i,...e}}),[i,e])}function s(e){let i;return i=e.disableParentContext?"function"==typeof e.components?e.components(t):e.components||t:c(e.components),n.createElement(o.Provider,{value:i},e.children)}}}]);