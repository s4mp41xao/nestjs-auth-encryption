import {
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';
import { AuthGuard } from '@nestjs/passport';
import { ROLES_KEY } from './roles.decorator';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  constructor(
    private readonly reflector: Reflector,
    private readonly jwtService: JwtService,
  ) {
    super();
  }

  async canActivate(context: ExecutionContext) {
    const canActivate = await super.canActivate(context);
    if (!canActivate) {
      return false;
    }

    const requiredRoles = this.reflector.getAllAndOverride<string[]>( // read "roles": ["admin"]
      ROLES_KEY,
      [context.getHandler(), context.getClass()],
    );

    if (!requiredRoles) {
      return true;
    }

    const request = context.switchToHttp().getRequest();

    const token = request.headers.authorization?.split(' ')[1];
    if (!token) {
      throw new UnauthorizedException('Token não autorizado');
    }

    const payload = this.jwtService.verify(token);
    const userRoles = payload.roles || [];
    const hasRoles = () =>
      userRoles.some((role) => requiredRoles.includes(role));
    if (!hasRoles()) {
      throw new UnauthorizedException('Permissões insuficientes');
    }
    return true;
  }
}
