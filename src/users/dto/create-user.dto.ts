import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsInt, IsNotEmpty, IsEmail } from 'class-validator';
import { BaseEntity } from 'src/base-entity';

export class CreateUserDto extends BaseEntity {
  @ApiProperty({
    description: 'User first name',
  })
  @IsString()
  @IsNotEmpty({ message: 'First Name is missing.' })
  first_name: string;

  @IsNotEmpty()
  @ApiProperty({
    description: 'User second name',
  })
  middle_name: string;

  @ApiProperty({
    description: 'User last name',
  })
  @IsString()
  @IsNotEmpty({ message: 'Last Name is missing.' })
  last_name: string;

  @ApiProperty({
    description: 'User age',
    type: String,
  })
  @IsString()
  age: string;

  @ApiProperty({
    description: 'User sex',
  })
  sex: string;

  @ApiProperty({
    description: 'User name',
  })
  @ApiProperty({
    description: 'Username',
  })
  username: string;

  @ApiProperty({
    description: 'Password',
  })
  password: string;

  @IsEmail()
  email: string;
}
