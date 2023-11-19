//src/auth/auth.service.ts
import {
    ConflictException,
    Injectable,
    NotFoundException,
    UnauthorizedException,
  } from '@nestjs/common';
  import { PrismaService } from './../prisma/prisma.service';
  import { JwtService } from '@nestjs/jwt';
  import { AuthEntity } from './entity/auth.entity';
  import { SignupDto } from './dto/singnup.dto';
  import * as bcrypt from 'bcrypt';

  @Injectable()
  export class AuthService {
    constructor(private prisma: PrismaService, private jwtService: JwtService) {}
  
    async login(email: string, password: string): Promise<AuthEntity> {
      // Step 1: Fetch a user with the given email
      const user = await this.prisma.user.findUnique({ where: { email: email } });
  
      // If no user is found, throw an error
      if (!user) {
        throw new NotFoundException(`No user found for email: ${email}`);
      }
  
      // Step 2: Check if the password is correct
      const isPasswordValid = await bcrypt.compare(password, user.password);
  
      // If password does not match, throw an error
      if (!isPasswordValid) {
        throw new UnauthorizedException('Invalid password');
      }
  
      // Step 3: Generate a JWT containing the user's ID and return it
      return {
        accessToken: this.jwtService.sign({ userId: user.id }),
      };
    }

    async signup(signupDto: SignupDto): Promise<AuthEntity> {
        const salt = await bcrypt.genSalt();
        // Check if the user with the given email already exists
        const existingUser = await this.prisma.user.findUnique({ where: { email: signupDto.email } });
        if (existingUser) {
          throw new ConflictException('User with this email already exists');
        }
    
        // If the user doesn't exist, create a new user
        const newUser = await this.prisma.user.create({
          data: {
            email: signupDto.email,
            name: signupDto.name,
            password: await bcrypt.hash(signupDto.password,salt), // Hash the password if needed
          },
        });
    
        // Generate and return a JWT for the new user
        return {
          accessToken: this.jwtService.sign({ userId: newUser.id }),
        };
    }
  }