/**
 * @swagger
 * components:
 *   schemas:
 *     User:
 *       type: object
 *       required:
 *         - name
 *         - email
 *         - tel
 *         - password
 *       properties:
 *         name:
 *           type: string
 *           description: Name of user
 *         email:
 *           type: string
 *           description: Email of user
 *         tel:
 *           type: string
 *           description: Telephone number of user
 *         role:
 *           type: string
 *           description: Role of user (admin or user), default is user
 *         password:
 *           type: string
 *           description: Password of user
 *         createdAt:
 *           type: string
 *           format: date
 *           example: '2023-08-20'
 *           description: Date of creation (default is current date-time)
 */

/**
 * @swagger
 * components:
 *   securitySchemes:
 *     bearerAuth:
 *       type: http
 *       scheme: bearer
 *       bearerFormat: JWT
 */

/**
 * @swagger
 * tags:
 *   name: User
 *   description: The user API
 */

const express = require("express");
const { register, login, getMe, logout } = require("../controllers/auth");
const {
  getUsers,
  getUser,
  updateUser,
  deleteUser,
} = require("../controllers/auth");
const router = express.Router();
const { protect } = require("../middleware/auth");
const { authorize } = require("../middleware/auth");

/**
 * @swagger
 * /auth/register:
 *   post:
 *     summary: Create a new user
 *     tags: [User]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/User'
 *     responses:
 *       201:
 *         description: The user was successfully created
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/User'
 *       500:
 *         description: Some server error
 */
router.post("/register", register);

/**
 * @swagger
 * /auth/login:
 *   post:
 *     summary: Log-in to the system
 *     tags: [User]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                   type: string
 *               password:
 *                   type: string
 *     responses:
 *       201:
 *         description: Log-in Successfully
 *       500:
 *         description: Some server error
 */
router.post("/login", login);
router.get("/logout", logout);

/**
 * @swagger
 * /auth/me:
 *   get:
 *     security:
 *       - bearerAuth: []
 *     summary: Return information about me
 *     tags: [User]
 *     responses:
 *       200:
 *         description: My user profile
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/User'
 *       500:
 *         description: Some server error
 */
router.get("/me", protect, getMe);

/**
 * @swagger
 * /auth:
 *   get:
 *     security:
 *       - bearerAuth: []
 *     summary: Get all users
 *     tags: [User]
 *     responses:
 *       200:
 *         description: List of all users
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/User'
 *       401:
 *         description: Not authorized
 *       403:
 *         description: Forbidden - Admin access only
 *       500:
 *         description: Some server error
 */

router.get("/", protect, authorize("admin"), getUsers);

/**
 * @swagger
 * /auth/{id}:
 *   get:
 *     security:
 *       - bearerAuth: []
 *     summary: Get user by ID
 *     tags: [User]
 *     parameters:
 *       - in: path
 *         name: id
 *         schema:
 *           type: string
 *         required: true
 *         description: User ID
 *     responses:
 *       200:
 *         description: User information retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/User'
 *       401:
 *         description: Not authorized
 *       403:
 *         description: Forbidden - Admin access only
 *       404:
 *         description: User not found
 *       500:
 *         description: Some server error
 */

router.get("/:id", protect, authorize("admin", "user"), getUser);

/**
 * @swagger
 * /auth/{id}:
 *   put:
 *     security:
 *       - bearerAuth: []
 *     summary: Update user
 *     tags: [User]
 *     parameters:
 *       - in: path
 *         name: id
 *         schema:
 *           type: string
 *         required: true
 *         description: User ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *               email:
 *                 type: string
 *               tel:
 *                  type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: User updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/User'
 *       401:
 *         description: Not authorized
 *       403:
 *         description: Forbidden - Admin access only
 *       404:
 *         description: User not found
 *       500:
 *         description: Some server error
 */

router.put("/:id", protect, authorize("admin", "user"), updateUser);

/**
 * @swagger
 * /auth/{id}:
 *   delete:
 *     security:
 *       - bearerAuth: []
 *     summary: Delete user
 *     tags: [User]
 *     parameters:
 *       - in: path
 *         name: id
 *         schema:
 *           type: string
 *         required: true
 *         description: User ID
 *     responses:
 *       200:
 *         description: User deleted successfully
 *       401:
 *         description: Not authorized
 *       403:
 *         description: Forbidden - Admin access only
 *       404:
 *         description: User not found
 *       500:
 *         description: Some server error
 */

router.delete("/:id", protect, authorize("admin"), deleteUser);

module.exports = router;
