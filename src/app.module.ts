import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

@Module({
  imports: [AuthModule],
  controllers: [AppController],
  providers: [AppService],
})

export class AppModule {
  // This method initializes Swagger documentation for your entire application
  static setupSwagger(app) {
    const config = new DocumentBuilder()
      .setTitle('Your API')
      .setDescription('API description')
      .setVersion('1.0')
      .build();

    const document = SwaggerModule.createDocument(app, config);
    SwaggerModule.setup('api', app, document);
  }
}