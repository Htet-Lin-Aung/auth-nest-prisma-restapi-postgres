import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from 'src/prisma/prisma.service';
import { LoginDto } from './dto/login.dto';
import { omit } from 'lodash';
import { compare } from 'bcrypt';
import { JwtConfig } from '../../jwt.config';

@Injectable()
export class AuthService {
    constructor(private jwtService: JwtService, private dbService: PrismaService) { }


    /**
     * Register Service
     * @param dto 
     * @returns 
     */
    async register(dto: any) {
        try{
            const user = await this.dbService.user.findFirst({
                where: {
                    email: dto.email
                }
            });
            if (user) {
                throw new HttpException('User Exists', HttpStatus.BAD_REQUEST);
            }
            const createUser = await this.dbService.user.create({
                data: dto
            })
            if (createUser) {
                return {
                    statusCode: 200,
                    message: 'Register success',
                };
            }
        }catch(error){
            throw new HttpException('Bad request', HttpStatus.BAD_REQUEST);
        }
    }


    /**
     * Login Service
     * @param dto 
     * @returns 
     */
    async login(dto: LoginDto) {
        try{
            const user = await this.dbService.user.findFirst({
                where: { email: dto.email }
            });

            if (!user) {
                throw new HttpException('User not found', HttpStatus.NOT_FOUND);
            }

            const checkPassword = await compare(dto.password, user.password);
            if (!checkPassword) {
                throw new HttpException('Credential Incorrect', HttpStatus.UNAUTHORIZED);
            }
            return await this.generateJwt(user);
        } catch (error) {        
            throw new HttpException('Login failed', HttpStatus.INTERNAL_SERVER_ERROR);
        }
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
    async generateJwt(user: any) {
        const accessToken = await this.jwtService.sign({
            sub: user.id,
            email: user.email,
            name: user.name
        }, {
            expiresIn: JwtConfig.user_expired,
            secret: JwtConfig.user_secret
        });

        const refreshToken = this.jwtService.sign(
        {
            sub: user.id,
            email: user.email,
            name: user.name
        },
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