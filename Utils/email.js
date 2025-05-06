const nodemailer = require("nodemailer");

require("dotenv").config();

if (!process.env.EMAIL_USER || !process.env.EMAIL_PASSWORD) {
  throw new Error("Email credentials are missing in environment variables.");
}

const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 587,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD,
  },
  tls: {
    rejectUnauthorized: false,
  },
  debug: true,
}); 

const sendVerificationEmail = async (email, token) => {
  const verificationLink = `https://foodstore-backend-nlzc.onrender.com/email-verification?token=${token}`;

  const mailOptions = {
    from: `"Food Store" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: "Verify Your Email",
    text: `Please verify your email by clicking the link below:\n\n${verificationLink}\n\nThank you!`, // Plain text version
    html: `
      <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif; line-height: 1.6; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 12px; background-color: #ffffff;">
        <!-- Header -->
        <div style="text-align: center; margin-bottom: 20px;">
          <h2 style="color: #1c1c1e; font-size: 24px; font-weight: 600;">Verify Your Email</h2>
          <p style="color: #8e8e93; font-size: 16px;">Welcome to Food Store! Let's get started.</p>
        </div>

        <!-- Content -->
        <div style="background-color: #f5f5f7; padding: 20px; border-radius: 8px; text-align: center;">
          <p style="color: #1c1c1e; font-size: 16px; margin-bottom: 20px;">
            Thank you for signing up with Food Store! To complete your registration, please verify your email address by clicking the button below:
          </p>

          <!-- Verification Button -->
          <a href="${verificationLink}" 
             style="display: inline-block; padding: 12px 24px; background-color: #007aff; color: #ffffff; text-decoration: none; border-radius: 8px; font-size: 16px; font-weight: 500; transition: background-color 0.3s ease;">
            Verify Email
          </a>
        </div>

        <!-- Fallback Instructions -->
        <div style="text-align: center; margin-top: 20px;">
          <p style="color: #8e8e93; font-size: 14px;">
            If the button above doesn't work, please copy and paste the following link into your browser:
          </p>
          <p style="color: #007aff; font-size: 14px; word-break: break-all;">
            <a href="${verificationLink}" style="color: #007aff; text-decoration: none;">${verificationLink}</a>
          </p>
        </div>

        <!-- Additional Help -->
        <div style="text-align: center; margin-top: 20px;">
          <p style="color: #8e8e93; font-size: 14px;">
            If you did not sign up for Food Store, please <a href="https://foodstore.com/unsubscribe" style="color: #007aff; text-decoration: none;">unsubscribe here</a>.
          </p>
        </div>

        <!-- Footer -->
        <div style="text-align: center; margin-top: 30px; font-size: 12px; color: #8e8e93;">
          <p>This email was sent by Food Store.</p>
          <p>© ${new Date().getFullYear()} Food Store. All rights reserved.</p>
        </div>
      </div>
    `,
  };

  try {
    // Send the email
    await transporter.sendMail(mailOptions);
    console.log("Verification email sent successfully");
  } catch (error) {
    console.error("Error sending verification email:", error);
    throw error;
  }
};

module.exports = { sendVerificationEmail };
