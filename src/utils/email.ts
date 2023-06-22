import { Prisma } from '@prisma/client';
import config from 'config';
import { convert } from 'html-to-text';
import nodemailer from 'nodemailer';
import pug from 'pug';

const smtp = config.get<{
  host: string;
  user: string;
  pass: string;
  port: number;
}>('smtp');

// SMTP configurations
export default class Email {
  firstName: string;
  from: string;
  to: string;
  constructor(private user: Prisma.UserCreateInput, private url: string) {
    this.firstName = user.name.split(' ')[0];
    this.to = user.email;
    this.from = 'tuanbe27 <admin@admin.com>';
  }

  // Transport
  private newTranspot() {
    return nodemailer.createTransport({
      ...smtp,
      auth: {
        user: smtp.user,
        pass: smtp.pass,
      },
    });
  }

  private async send(template: string, subject: string) {
    // Generate HTML template based on the template string
    const html = pug.renderFile(`${process.cwd()}/src/views/${template}.pug`, {
      firstName: this.firstName,
      subject,
      url: this.url,
    });

    // Create mailOptions
    const mailOptions = {
      from: this.from,
      to: this.to,
      subject,
      text: convert(html),
      html,
    };

    // Send email
    const info = await this.newTranspot().sendMail(mailOptions);
    console.log(nodemailer.getTestMessageUrl(info));
  }

  async sendVerificationCode() {
    await this.send('verificationCode', 'Your account verification code');
  }

  async sendPasswordResetToken() {
    await this.send(
      'resetPassword',
      'Your password reset token (valid for only 10 minutes)'
    );
  }
}
