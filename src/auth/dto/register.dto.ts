// src/auth/dto/signup.dto.ts

import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsPhoneNumber, IsString, Matches, MaxLength, MinLength, Equals } from 'class-validator';

export class RegisterDto {
  @IsPhoneNumber()
  @IsNotEmpty()
  @ApiProperty()
  phone: string;

  @IsString()
  @IsNotEmpty()
  @ApiProperty()
  name: string;

  @IsString()
  @MinLength(6)
  @MaxLength(20)
  @IsNotEmpty()
  @ApiProperty()
  password: string;
}
