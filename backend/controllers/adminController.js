import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";

import { Admin, OTP } from "../models/Admin.js";
import { sendOTPEmail } from "../utils/emailService.js";
import { sendOTPReset } from "../utils/emailService.js";
import { generateOTP } from "../utils/helpers.js";

//---------------------------------------------------------

/**
 * 1️⃣ FORGOT PASSWORD - SEND OTP
 */
export const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: "Email is required",
      });
    }

    // Check if admin exists
    const admin = await Admin.findOne({ email });
    if (!admin) {
      return res.status(404).json({
        success: false,
        message: "Admin with this email does not exist",
      });
    }

    // Generate OTP
    const otp = generateOTP();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 min expiry

    // Delete old OTP if any
    await OTP.deleteMany({ email, type: "forgot-password" });

    // Store OTP in DB
    const otpRecord = new OTP({
      email,
      otp,
      expiresAt,
      type: "forgot-password",
    });
    await otpRecord.save();

    // Send OTP email
    await sendOTPReset(email, otp, admin.name);

    res.json({
      success: true,
      message: "OTP sent to your email for password reset",
    });
  } catch (error) {
    console.error("Forgot password error:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

/**
 * 2️⃣ VERIFY OTP FOR PASSWORD RESET
 */
export const verifyForgotPasswordOTP = async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({
        success: false,
        message: "Email and OTP are required",
      });
    }

    // Find OTP record
    const otpRecord = await OTP.findOne({
      email,
      otp,
      type: "forgot-password",
    });
    if (!otpRecord) {
      return res.status(400).json({
        success: false,
        message: "Invalid OTP",
      });
    }

    // Check if OTP expired
    if (new Date() > otpRecord.expiresAt) {
      await OTP.deleteOne({ _id: otpRecord._id });
      return res.status(400).json({
        success: false,
        message: "OTP has expired",
      });
    }

    // OTP valid → allow password reset
    await OTP.deleteOne({ _id: otpRecord._id });

    res.json({
      success: true,
      message: "OTP verified successfully. You can now reset your password.",
    });
  } catch (error) {
    console.error("Verify forgot password OTP error:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

/**
 * 3️⃣ RESET PASSWORD
 */
export const resetPassword = async (req, res) => {
  try {
    const { email, newPassword } = req.body;

    if (!email || !newPassword) {
      return res.status(400).json({
        success: false,
        message: "Email and new password are required",
      });
    }

    // Check if admin exists
    const admin = await Admin.findOne({ email });
    if (!admin) {
      return res.status(404).json({
        success: false,
        message: "Admin not found",
      });
    }

    // ✅ Hash new password manually
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    // ✅ Update only the password (skip validation on other fields like name)
    await Admin.updateOne({ email }, { $set: { password: hashedPassword } });

    res.json({
      success: true,
      message: "Password reset successful. You can now log in.",
    });
  } catch (error) {
    console.error("Reset password error:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

//---------------------------------------------------------

export const signup = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Validation
    if (!name || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "All fields are required",
      });
    }

    // Check if admin already exists
    const existingAdmin = await Admin.findOne({ email });
    if (existingAdmin) {
      return res.status(400).json({
        success: false,
        message: "Admin with this email already exists",
      });
    }

    // Create admin
    const admin = new Admin({
      name,
      email,
      password,
    });

    await admin.save();

    // Generate and store OTP
    const otp = generateOTP();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    // Remove any existing OTP for this email
    await OTP.deleteMany({ email });

    // Store new OTP
    const otpRecord = new OTP({
      email,
      otp,
      expiresAt,
      type: "signup",
    });
    await otpRecord.save();

    // Send OTP email
    await sendOTPEmail(email, otp, name, "signup");

    res.status(201).json({
      success: true,
      message: "Admin created successfully. OTP sent to email.",
      adminId: admin._id,
    });
  } catch (error) {
    console.error("Signup error:", error);

    // Handle validation errors
    if (error.name === "ValidationError") {
      const messages = Object.values(error.errors).map((err) => err.message);
      return res.status(400).json({
        success: false,
        message: messages.join(", "),
      });
    }

    // Handle duplicate key error
    if (error.code === 11000) {
      return res.status(400).json({
        success: false,
        message: "Admin with this email already exists",
      });
    }

    res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

export const verifyOTP = async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({
        success: false,
        message: "Email and OTP are required",
      });
    }

    // Find OTP record
    const otpRecord = await OTP.findOne({ email, otp, type: "signup" });
    if (!otpRecord) {
      return res.status(400).json({
        success: false,
        message: "Invalid OTP",
      });
    }

    // Check if OTP is expired
    if (new Date() > otpRecord.expiresAt) {
      await OTP.deleteOne({ _id: otpRecord._id });
      return res.status(400).json({
        success: false,
        message: "OTP has expired",
      });
    }

    // Update admin as verified
    const admin = await Admin.findOneAndUpdate(
      { email },
      { isVerified: true },
      { new: true }
    );

    if (!admin) {
      return res.status(400).json({
        success: false,
        message: "Admin not found",
      });
    }

    // Clean up OTP
    await OTP.deleteOne({ _id: otpRecord._id });

    res.json({
      success: true,
      message: "Account verified successfully",
    });
  } catch (error) {
    console.error("OTP verification error:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

export const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Email and password are required",
      });
    }

    // Find admin
    const admin = await Admin.findOne({ email });
    if (!admin) {
      return res.status(400).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    // Check if admin is verified
    if (!admin.isVerified) {
      return res.status(400).json({
        success: false,
        message: "Please verify your account first",
      });
    }

    // Verify password
    const isPasswordValid = await admin.comparePassword(password);
    if (!isPasswordValid) {
      return res.status(400).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    // Generate and store OTP for login
    const otp = generateOTP();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    // Remove any existing login OTP for this email
    await OTP.deleteMany({ email, type: "login" });

    // Store new OTP
    const otpRecord = new OTP({
      email,
      otp,
      expiresAt,
      type: "login",
    });
    await otpRecord.save();

    // Send OTP email
    await sendOTPEmail(email, otp, admin.name, "login");

    res.json({
      success: true,
      message: "OTP sent to your email for login verification",
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

export const verifyLoginOTP = async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({
        success: false,
        message: "Email and OTP are required",
      });
    }

    // Find OTP record
    const otpRecord = await OTP.findOne({ email, otp, type: "login" });
    if (!otpRecord) {
      return res.status(400).json({
        success: false,
        message: "Invalid OTP",
      });
    }

    // Check if OTP is expired
    if (new Date() > otpRecord.expiresAt) {
      await OTP.deleteOne({ _id: otpRecord._id });
      return res.status(400).json({
        success: false,
        message: "OTP has expired",
      });
    }

    // Find admin
    const admin = await Admin.findOne({ email });
    if (!admin) {
      return res.status(400).json({
        success: false,
        message: "Admin not found",
      });
    }

    // Generate JWT token
    const token = jwt.sign(
      { adminId: admin._id, email: admin.email },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    // Clean up OTP
    await OTP.deleteOne({ _id: otpRecord._id });

    res.json({
      success: true,
      message: "Login successful",
      token,
      admin: admin.toJSON(),
    });
  } catch (error) {
    console.error("Login OTP verification error:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};
