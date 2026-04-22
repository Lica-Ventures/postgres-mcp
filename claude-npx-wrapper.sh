#!/bin/bash
# Wrapper so Claude Desktop runs npm under Node 24 w/ ReadableStream
export PATH="/Users/paul-devbox/.nvm/versions/node/v24.12.0/bin:$PATH"
exec /Users/paul-devbox/.nvm/versions/node/v24.12.0/bin/npx "$@"
