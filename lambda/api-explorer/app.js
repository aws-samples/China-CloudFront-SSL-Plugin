const express = require('express')
const serverless = require('serverless-http')
const swaggerUI = require('swagger-ui-express')

const swaggerDocument = require('./app.json')
swaggerDocument.servers = [{ url: process.env.SWAGGER_SPEC_URL }];

const app = express()
app.use(
    '/api-explorer',
    swaggerUI.serve,
    swaggerUI.setup(swaggerDocument)
)

module.exports.handler = serverless(app)