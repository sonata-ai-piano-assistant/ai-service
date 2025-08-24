require("dotenv").config()
const express = require("express")
const cors = require("cors")
const apiRoutes = require("./routes")
const app = express()
const PORT = process.env.PORT || 3001
const {
  initializeMetrics,
  metricsMiddleware,
  metricsRouter
} = require("./utils/metrics")
const loggerMiddleware = require("./middlewares/logger.middleware")
const errorHandlingMiddleware = require("./middlewares/errorHandling")
app.use(express.json())
app.use(
  cors({
    origin: process.env.FRONTEND_URL,
    methods: ["GET", "POST"],
    credentials: true
  })
)
// 🔧 INITIALISATION DES MÉTRIQUES
initializeMetrics("ai")

// 📊 MIDDLEWARE MÉTRIQUES
app.use(metricsMiddleware)
app.use(loggerMiddleware)
// 🛣️ ROUTES MÉTRIQUES
app.use(metricsRouter)
// Routes
app.use("/api", apiRoutes)
app.use(errorHandlingMiddleware)
// Lancer le serveur
app.listen(PORT, () => console.log(`🎵 Server running on port ${PORT}`))
