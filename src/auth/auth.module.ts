import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtStrategy } from './jwt-auth/jwt.strategy';
import { JwtConfig } from '../../jwt.config';
import { PrismaService } from 'src/prisma/prisma.service';
import { MulterModule } from '@nestjs/platform-express';
import { diskStorage } from 'multer';
import { extname } from 'path';
import { v4 as uuidv4 } from 'uuid';

@Module({
  imports: [
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.register({
      secret: JwtConfig.user_secret,
      signOptions: {
        expiresIn: JwtConfig.user_expired,
      },
    }),
    // MulterModule.register({dest: './uploads'})
    MulterModule.register({
      dest: './uploads',
      // storage: diskStorage({
      //   destination: (req, file, cb) => {
      //     cb(null, 'uploads');
      //   },
      //   filename: (req, file, cb) => {
      //     const randomName = uuidv4();
      //     cb(null, `${randomName}${extname(file.originalname)}`);
      //   },
      // }),
    }),
  ],
  providers: [AuthService, JwtStrategy,PrismaService],
  controllers: [AuthController]
})
export class AuthModule { }