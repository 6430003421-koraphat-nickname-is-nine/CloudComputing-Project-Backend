const User = require("../models/User");

//@desc     Register user
//@route    POST /api/v1/auth/register
//@access   Public
exports.register = async (req, res, next) => {
  try {
    const { name, email, tel, password, role } = req.body;
    const user = await User.create({
      name,
      email,
      tel,
      password,
      role,
    });
    sendTokenResponse(user, 200, res);
  } catch (err) {
    res.status(400).json({
      success: false,
      message: err.keyValue.email ? "Email already exists" : "Cannot create User",
    });
    console.log(err.stack);
  }
};

//@desc   Login user
//@route  POST /api/v1/auth/login
//@access Public
exports.login = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res
        .status(400)
        .json({ success: false, msg: "Please provide an email and password" });
    }
    const user = await User.findOne({ email }).select("+password");
    if (!user) {
      return res.status(400).json({
        success: false,
        msg: "Invalid credentials",
      });
    }
    const isMatch = await user.matchPassword(password);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        msg: "Invalid credentials",
      });
    }
    sendTokenResponse(user, 200, res);
  } catch (err) {
    return res.status(401).json({
      success: false,
      msg: "Cannot convert email or password to string",
    });
  }
};

const sendTokenResponse = (user, statusCode, res) => {
  const token = user.getSignedJwtToken();
  const options = {
    expires: new Date(
      Date.now() + process.env.JWT_COOKIE_EXPIRE * 24 * 60 * 60 * 1000
    ),
    httpOnly: true,
  };
  if (process.env.NODE_ENV === "production") {
    options.secure = true;
  }
  res.status(statusCode).cookie("token", token, options).json({
    success: true,
    _id: user._id,
    name: user.name,
    email: user.email,
    role: user.role,
    token,
  });
};

//@desc   Get current Logged in user
//@route  POST /api/v1/auth/me
//@access Private
exports.getMe = async (req, res, next) => {
  const user = await User.findById(req.user.id);
  res.status(200).json({
    success: true,
    data: user,
  });
};

//@desc   Log user out / clear cookie
//@route  GET /api/v1/auth/logout
//@access Private
exports.logout = async (req, res, next) => {
  res.cookie("token", "none", {
    expires: new Date(Date.now() + 10 * 1000),
    httpOnly: true,
  });
  res.status(200).json({
    success: true,
    data: {},
  });
};

//@desc   Get  Users
//@route  get /api/v1/auth/:id
//@access Private
exports.getUsers = async (req, res, next) => {
  try {
    const users = await User.find();
    res.status(200).json({ success: true, data: users });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      success: false,
      message: "Cannot find User",
    });
  }
};

//@desc   Get  User by id
//@route  get /api/v1/auth/:id
//@access Private
exports.getUser = async (req, res, next) => {
  let user;
  try {
    user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: `No user with the id of ${req.params.id}`,
      });
    }
    res.status(200).json({ success: true, data: user });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      success: false,
      message: "Cannot find User",
    });
  }
};

//@desc   Update User by id
//@route  get /api/v1/auth/:id
//@access Private
exports.updateUser = async (req, res, next) => {
  try {
    const user = await User.findById(req.params.id);

    if (!user) {
      return res.status(400).json({ success: false });
    }

    if (req.params.id !== req.user.id && req.user.role !== "admin") {
      return res.status(401).json({
        success: false,
        message: `User ${req.user.id} is not authorized to update this user`,
      });
    }

    // If password is being updated, use save() to trigger middleware
    if (req.body.password) {
      Object.assign(user, req.body);
      await user.save();
    } else {
      // For non-password updates, use findByIdAndUpdate
      await User.findByIdAndUpdate(req.params.id, req.body, {
        new: true,
        runValidators: true,
      });
    }

    res.status(200).json({ success: true, data: user });
  } catch (error) {
    res.status(400).json({ success: false });
  }
};

//@desc   Delete User by id
//@route  DELETE /api/v1/auth/:id
//@access Private
exports.deleteUser = async (req, res, next) => {
  try {
    const user = await User.findById(req.params.id);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: `No user with the id of ${req.params.id}`,
      });
    }

    // Make sure user is deleting their own account or is admin
    if (req.params.id !== req.user.id && req.user.role !== "admin") {
      return res.status(401).json({
        success: false,
        message: `User ${req.user.id} is not authorized to delete this user`,
      });
    }

    await user.remove();

    res.status(200).json({
      success: true,
      data: {},
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Cannot delete User",
    });
  }
};
