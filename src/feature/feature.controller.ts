import { Controller, Get, UseGuards } from '@nestjs/common';
import { CurrentUser } from 'src/auth/dto/current-user.decorator';
import { CurrentUserDTO } from 'src/auth/dto/current-user.dto';
import { JwtAuthGuard } from 'src/auth/jwt-auth.guard';
import { Roles } from 'src/auth/roles.decorator';

@Controller('feature')
export class FeatureController {
  @Get('public')
  getPublicFeature() {
    return 'This is a public feature';
  }

  @Get('private')
  @UseGuards(JwtAuthGuard)
  getPrivateFeature(@CurrentUser() user: CurrentUserDTO) {
    return `This is a private feature ${user.username}`;
  }

  @Get('admin')
  @Roles('admin')
  @UseGuards(JwtAuthGuard)
  getAdminFeature() {
    return 'This is a admin route';
  }
}
