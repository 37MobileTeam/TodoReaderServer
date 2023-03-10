import App
import Vapor

var env = try Environment.detect()
try LoggingSystem.bootstrap(from: &env)
let app = Application(env)
#if DEBUG
app.http.server.configuration.port = 8090
#else
app.http.server.configuration.port = 8091
#endif
defer { app.shutdown() }
try configure(app)
try app.run()
