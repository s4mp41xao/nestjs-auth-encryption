import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { randomBytes, scrypt as _scrypt, UUID } from 'crypto';
import { access } from 'fs';
import { promisify } from 'util';
import { v4 as uuid } from 'uuid';

const scrypt = promisify(_scrypt);

const users: {
  email: string;
  password: string;
  id: string;
  roles: string[];
}[] = [];

const refreshTokens: { value: string }[] = [];

@Injectable()
export class AuthService {
  constructor(private readonly jwtService: JwtService) {}

  async signUp(email: string, password: string, roles: string[] = []) {
    const existngUser = users.find((user) => user.email === email);
    if (existngUser) {
      return new BadRequestException('Email em uso');
    }

    const salt = randomBytes(8).toString('hex');
    const hash = (await scrypt(password, salt, 32)) as Buffer;
    const saltAndHash = `${salt}.${hash.toString('hex')}`;

    const user = {
      email,
      password: saltAndHash,
      id: uuid(),
      roles,
    };

    users.push(user);

    console.log('Usuário registrado', user);
    const { password: _, ...result } = user;
    return result;
  }

  async signIn(email: string, password: string) {
    const user = users.find((user) => user.email === email);
    if (!user) {
      return new UnauthorizedException('Credenciais inválidas');
    }

    const [salt, storedHash] = user.password.split('.');
    const hash = (await scrypt(password, salt, 32)) as Buffer;

    if (storedHash != hash.toString('hex')) {
      return new UnauthorizedException('Credenciais inválidas');
    }

    console.log('Usuário logado', user);
    const payload = {
      username: user.email,
      sub: user.id,
      roles: user.roles,
    };

    const accessToken = this.jwtService.sign(
      { ...payload, type: 'access' },
      { expiresIn: '60s' },
    );

    const refreshToken = this.jwtService.sign(
      { ...payload, type: 'refresh' },
      { expiresIn: '1h' },
    );

    refreshTokens.push({ value: refreshToken });

    return { accessToken, refreshToken };
  }

  async refresh(refreshToken: string) {
    const storedToken = refreshTokens.find(
      (token) => token.value === refreshToken,
    );
    if (!storedToken) {
      throw new UnauthorizedException('Refresh token inválido');
    }

    const payload = this.jwtService.verify(refreshToken);
    if (payload.type !== 'refresh') {
      throw new UnauthorizedException('Tipo de token inválido');
    }

    const user = users.find((user) => user.id === payload.sub);
    if (!user) {
      throw new UnauthorizedException('Refresh token inválido');
    }

    const newPayload = {
      username: user.email,
      sub: user.id,
      roles: user.roles,
    };

    const newAccessToken = this.jwtService.sign(
      { ...newPayload, type: 'access' },
      { expiresIn: '60s' },
    );

    const newRefreshToken = this.jwtService.sign(
      { ...newPayload, type: 'refresh' },
      { expiresIn: '1h' },
    );

    storedToken.value = newRefreshToken;

    return { accessToken: newAccessToken, refreshToken: newRefreshToken };
  }
}
