const loggerMiddleware = (req, res, next) => {
  const start = Date.now()

  res.on("finish", () => {
    const duration = Date.now() - start
    console.log({
      ip: req.ip,
      userAgent: req.headers["user-agent"],
      method: req.method,
      url: req.originalUrl,
      status: res.statusCode,
      duration
    })
  })

  next()
}

module.exports = loggerMiddleware
