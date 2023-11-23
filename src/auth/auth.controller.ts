import { RefreshDto } from './dto/refresh.dto';
import { Body, Controller, Get, HttpCode, Post, UploadedFile, UseGuards, UseInterceptors, UsePipes, ValidationPipe } from '@nestjs/common';
import { ApiBody, ApiConsumes, ApiTags } from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { JwtAuthGuard } from './jwt-auth/jwt-auth.guard';
import { TransformPasswordPipe } from './transform-password.pipe';
import { FileInterceptor } from '@nestjs/platform-express';
import { diskStorage } from 'multer';
import { extname } from 'path';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {

    /**
     * Constructor
     * @param authService 
     */
    constructor(private authService: AuthService) {

    }

    /**
     * Register controller
     * @param dto 
     * @returns 
     */
    @UsePipes(ValidationPipe, TransformPasswordPipe)
    @HttpCode(200)
    @Post('register')
    @ApiConsumes('multipart/form-data')
    @UseInterceptors(FileInterceptor('profile',{
        storage: diskStorage({
            destination: './uploads',
            filename: (req, file, cb) => {
                const randomName = Array(32).fill(null).map(() => (Math.round(Math.random() * 16)).toString(16)).join('')
                return cb(null, `${randomName}${extname(file.originalname)}`)
            }
        }),
    }))
    async register(@Body() dto: RegisterDto, @UploadedFile() profile: Express.Multer.File) {
        return await this.authService.register(dto,profile);
    }

    /**
     * Login Controller
     * @param dto 
     * @returns 
     */
    @UsePipes(ValidationPipe)
    @HttpCode(200)
    @Post('login')
    async login(@Body() dto: LoginDto) {
        return await this.authService.login(dto);
    }

    @Post('refreshToken')
    async refreshToken(@Body() refreshDto: RefreshDto) {
        return this.authService.refreshToken(refreshDto.refreshToken);
    }
}