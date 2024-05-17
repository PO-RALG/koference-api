import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Role } from './entities/role.enum';
import { AuthService } from 'src/auth/auth.service';
import { UsersService } from './users.service';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(
    private reflector: Reflector,
    private readonly authService: AuthService,
    private readonly userService: UsersService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const requreRoles = this.reflector.getAllAndOverride<any[]>('roles', [
      context.getHandler(),
      context.getClass,
    ]);

    if (!requreRoles) {
      return true;
    }

    const user = context.switchToHttp().getRequest();
    // console.log('user user user', user.rawHeaders);

    // To ensure you always get the correct index for the Authorization header,
    //  you can iterate over the rawHeaders array to find the index dynamically.
    //  Here's the code to find the token index:

    let tokenIndex: number | undefined;
    user.rawHeaders.forEach((header, index) => {
      if (header.toLowerCase() === 'authorization') {
        tokenIndex = index + 1;
      }
    });
    console.log('tokenIndex', tokenIndex);

    if (tokenIndex === undefined) {
      // console.log('Authorization header not found');
      return false;
    }

    const token = user.rawHeaders[tokenIndex]?.replace('Bearer ', '');
    // console.log('token', token);

    const decoded = await this.authService.verifyToken(token);
    const user1 = await this.userService.findOne(decoded.sub);
    const roleNames = user1.roles.map((role) => role.name);
    // console.log('roleNames', roleNames);

    return requreRoles.some((role) => roleNames.includes(role));
  }
}
