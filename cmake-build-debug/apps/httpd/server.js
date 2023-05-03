const https = require('https');
const fs = require('fs');

const options = {
    key: fs.readFileSync('/home/daniel/Desktop/seastar_quic/cmake-build-debug/apps/httpd/localhost-key.pem'),
    cert: fs.readFileSync('/home/daniel/Desktop/seastar_quic/cmake-build-debug/apps/httpd/localhost.pem'),
};

const PORT = 2138;

const server = https.createServer(options, function (req, res) {
    res.writeHead(200, {
        'Content-Type': 'text/html',
        'alt-svc': 'h3=":3333"'
    });
    res.end('<b>You\'re using HTTP over TCP!<b>');
});

server.listen(PORT, function() {
    console.log(`Server listening on port ${PORT}`);
});
