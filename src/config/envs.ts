import 'dotenv/config'
import * as Joi from 'joi'

interface EnvVars {
  PORT: number

  NATS_SERVERS: string[]

  JWT_SECRET: string
}

const envsSchema = Joi.object({
  PORT: Joi.number().required(),

  NATS_SERVERS: Joi.array().items(Joi.string()).required(),
  JWT_SECRET: Joi.string().required(),
}).unknown(true)

const { error, value } = envsSchema.validate({
  ...process.env,
  NATS_SERVERS: process.env.NATS_SERVERS?.split(','),
})

if (error) {
  throw new Error(`Config validation error: ${error.message}`)
}
const envsVars: EnvVars = value
export const envs = {
  port: envsVars.PORT,

  natsServers: envsVars.NATS_SERVERS,
  jwtSecret: envsVars.JWT_SECRET,
}
