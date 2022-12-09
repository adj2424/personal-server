A personal secure server implementation.

src - contains the base code's source files.
tests - contains unit tests, performance tests, and associated files.
react-app - contains a JavaScript web app.
sfi - contains documentation for the 'server fuzzing interface'.
Get Started
Run the script: ./install-dependencies.sh. Then, cd into src and type make to build the base code.

To implement our multithreaded server, we decided to spawn a new thread per client instead of using a threadpool. Our server will be listening on a user specified port in an infinite loop and use a user defined root path. Once there is a connection with the client, our server will parse the request into the method type, and http version. It can also parse headers. Our server has multiple functions like token-based authentification, HTTP/1.0 and HTTP/1.1 implementaions, handling files such as mp4 and more. The server is designed to also get partial content for mp4 if there is a header for the byte range. For token-based authentification, we used jwt and hs256 for our hashing algorithm with a sub, iat, and exp grants.

