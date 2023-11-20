import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from 'src/prisma/prisma.service';
import { LoginDto } from './dto/login.dto';
import { omit } from 'lodash';
import { compare } from 'bcrypt';
import { JwtConfig } from 'src/jwt.config';

@Injectable()
export class AuthService {
    constructor(private jwtService: JwtService, private dbService: PrismaService) { }


    /**
     * Register Service
     * @param dto 
     * @returns 
     */
    async register(dto: any) {
        let user = await this.dbService.user.findFirst({
            where: {
                email: dto.email
            }
        });
        if (user) {
            throw new HttpException('User Exists', HttpStatus.BAD_REQUEST);
        }
        let createUser = await this.dbService.user.create({
            data: dto
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
        let user = await this.dbService.user.findFirst({
            where: { email: dto.email }
        });

        if (!user) {
            throw new HttpException('User not found', HttpStatus.NOT_FOUND);
        }

        let checkPassword = await compare(dto.password, user.password);
        if (!checkPassword) {
            throw new HttpException('Credential Incorrect', HttpStatus.UNAUTHORIZED);
        }
        return await this.generateJwt(user);
    }

    /**
     * Generate JWT
     * @param user 
     * @returns 
     */
    async generateJwt(user: any) {
        let accessToken = await this.jwtService.sign({
            sub: user.id,
            email: user.email,
            name: user.name
        }, {
            expiresIn: JwtConfig.user_expired,
            secret: JwtConfig.user_secret
        });
        return {
            statusCode: 200,
            accessToken: accessToken,
            user: omit(user, ['password','created_at','updated_at'])
        };
    }

}