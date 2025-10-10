const http = require('http');
const mkdirp = require('mkdirp');

const server = http.createServer(async (req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  // Use mkdirp just to show it's a dependency
  try {
    await mkdirp('./tmp-dir-from-app');
    res.end('Hello World! Directory created.');
  } catch (err) {
    console.error(err);
    res.statusCode = 500;
    res.end(`Hello World! Error creating directory: ${err.message}`);
  }
});

const PORT = 3000;
server.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}/`);
});
