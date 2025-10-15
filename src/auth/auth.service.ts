import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { randomBytes, scrypt as _scrypt } from 'crypto';
import { promisify } from 'util';

const scrypt = promisify(_scrypt);

const users: { email: string; password: string }[] = [];

@Injectable()
export class AuthService {
  async signUp(email: string, password: string) {
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
    const { password: _, ...result } = user;
    return result;
  }
}
