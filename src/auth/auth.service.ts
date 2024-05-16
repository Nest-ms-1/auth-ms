import { Injectable, Logger, OnModuleInit } from '@nestjs/common'
import { RpcException } from '@nestjs/microservices'
import { PrismaClient } from '@prisma/client'
import { LoginUserDto, RegisterUserDto } from './dto'
import * as bcrypt from 'bcrypt'
import { JwtService } from '@nestjs/jwt'
import { JwtPayload } from './interfaces'
import { envs } from 'src/config'

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
  private readonly logger = new Logger('AuthService')

  constructor(private readonly jwtService: JwtService) {
    super()
  }

  onModuleInit() {
    this.$connect()
    this.logger.log('MongoDB Connected Successfully')
  }

  async singJwtToken(payload: JwtPayload) {
    return this.jwtService.sign(payload)
  }

  async verifyToken(token: string) {
    try {
      const { sub, iat, exp, ...user } = this.jwtService.verify(token, {
        secret: envs.jwtSecret,
      })

      return {
        user: user,
        token: await this.singJwtToken(user),
      }
    } catch (error) {
      throw new RpcException({
        status: 401,
        message: 'Invalid token',
      })
    }
  }

  async registerUser(registerUserDto: RegisterUserDto) {
    const { email, password, name } = registerUserDto
    try {
      const user = await this.user.findUnique({
        where: {
          email,
        },
      })

      if (user) {
        throw new RpcException({
          status: 400,
          message: 'User already exists',
        })
      }

      const newUser = await this.user.create({
        data: {
          email: email,
          password: bcrypt.hashSync(password, 10),
          name: name,
        },
      })

      const { password: _, ...userWithoutPassword } = newUser

      return {
        user: userWithoutPassword,
        token: await this.singJwtToken(userWithoutPassword),
      }
    } catch (error) {
      throw new RpcException({
        status: 400,
        message: error.message,
      })
    }
  }

  async loginUser(loginUserDto: LoginUserDto) {
    const { email, password } = loginUserDto
    try {
      const user = await this.user.findUnique({
        where: { email },
      })

      if (!user) {
        throw new RpcException({
          status: 400,
          message: 'User not found',
        })
      }

      const isPasswordValid = bcrypt.compareSync(password, user.password)

      if (!isPasswordValid) {
        throw new RpcException({
          status: 400,
          message: 'Invalid password',
        })
      }

      const { password: _, ...userWithoutPassword } = user

      return {
        user: userWithoutPassword,
        token: await this.singJwtToken(userWithoutPassword),
      }
    } catch (error) {
      throw new RpcException({
        status: 400,
        message: error.message,
      })
    }
  }
}
