import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from 'src/prisma/prisma.service';
import { LoginDto } from './dto/login.dto';
import { omit } from 'lodash';
import { compare } from 'bcrypt';
import { JwtConfig } from '../../jwt.config';
import { RegisterDto } from './dto/register.dto';
import { User } from '@prisma/client';

@Injectable()
export class AuthService {
    constructor(private jwtService: JwtService, private dbService: PrismaService) { }

    /**
     * Register Service
     * @param dto 
     * @returns 
     */
    async register(dto: RegisterDto, profile: Express.Multer.File) {
        const user = await this.dbService.user.findFirst({
            where: {
                phone: dto.phone
            }
        });
        if (user) {
            throw new HttpException('User Exists', HttpStatus.BAD_REQUEST);
        }

        const filePath = '/uploads/' + profile.filename;

        const createUser = await this.dbService.user.create({
            data: {...dto, profile: filePath}
        })
        if (createUser) {
            return {
                statusCode: 200,
                message: 'Register success',
            };
        }
        throw new HttpException('Bad request', HttpStatus.BAD_REQUEST);
    }


    /**
     * Login Service
     * @param dto 
     * @returns 
     */
    async login(dto: LoginDto) {
        const user = await this.dbService.user.findFirst({
            where: { phone: dto.phone }
        });

        if (!user) {
            throw new HttpException('User not found', HttpStatus.NOT_FOUND);
        }

        const checkPassword = await compare(dto.password, user.password);
        if (!checkPassword) {
            throw new HttpException('Credential Incorrect', HttpStatus.UNAUTHORIZED);
        }
        return await this.generateJwt(user);
    }

    async refreshToken(refreshToken: string) {
        try {
          const decodedToken = this.jwtService.verify(refreshToken, {
            secret: JwtConfig.refresh_token_secret,
          });
        
          const user = await this.dbService.user.findFirst({
            where: { id: decodedToken.sub },
          });
    
          if (!user) {
            throw new HttpException('User not found', HttpStatus.NOT_FOUND);
          }
          
          return await this.generateJwt(user);
        } catch (error) {
            throw new HttpException('Invalid refresh token', HttpStatus.UNAUTHORIZED);
        }
    }
    
    /**
     * Generate JWT
     * @param user 
     * @returns 
    */
   async generateJwt(user: User) {
       const payload = { sub: user.id, username: user.name, phone: user.phone };
       const accessToken = await this.jwtService.sign(payload, 
        {
            expiresIn: JwtConfig.user_expired,
            secret: JwtConfig.user_secret
        });

        const refreshToken = this.jwtService.sign(payload,
        {
            expiresIn: JwtConfig.refresh_token_expired,
            secret: JwtConfig.refresh_token_secret,
        },
        );

        return {
            statusCode: HttpStatus.OK,
            accessToken: accessToken,
            refreshToken: refreshToken,
            user: omit(user, ['password','created_at','updated_at'])
        };
    }
}