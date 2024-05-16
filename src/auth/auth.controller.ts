import { Controller } from '@nestjs/common'
import { AuthService } from './auth.service'
import { MessagePattern, Payload, RpcException } from '@nestjs/microservices'
import { LoginUserDto, RegisterUserDto } from './dto'
import { catchError } from 'rxjs'

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @MessagePattern('auth.register.user')
  registerUser(@Payload() registerUserDto: RegisterUserDto) {
    return this.authService.registerUser(registerUserDto)
  }
  @MessagePattern('auth.login.user')
  loginUser(@Payload() loginUserDto: LoginUserDto) {
    return this.authService.loginUser(loginUserDto)
  }
  @MessagePattern('auth.verify.token')
  verifyToken(@Payload() token: string) {
    return this.authService.verifyToken(token)
  }
}
