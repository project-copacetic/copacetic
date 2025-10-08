const http = require('http');
const _ = require('lodash');

const server = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  // Use lodash just to show it's a dependency
  const message = _.join(['Hello', 'Vulnerable', 'World'], ' ');
  res.end(message);
});

const PORT = 3000;
server.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}/`);
});