let express = require('express');
let router = express.Router()
let userController = require('../controllers/users')
let bcrypt = require('bcrypt')
let authHandler = require('../utils/authHandler')
const { body, validationResult } = require('express-validator');

router.post('/register', async function (req, res, next) {
    try {
        let { username, password, email } = req.body;
        let newUser = await userController.CreateAnUser(username, password, email,
            "69b1265c33c5468d1c85aad8"
        )
        res.send(newUser)
    } catch (error) {
        res.status(404).send({
            message: error.message
        })
    }
})
router.post('/login', async function (req, res, next) {
    try {
        let { username, password } = req.body;
        let user = await userController.GetAnUserByUsername(username);
        if (!user) {
            res.status(404).send({
                message: "thong tin dang nhap khong dung"
            })
            return;
        }
        if (user.lockTime > Date.now()) {
            res.status(404).send({
                message: "ban dang bi ban"
            })
            return;
        }
        if (bcrypt.compareSync(password, user.password)) {
            user.loginCount = 0;
            await user.save()
            const token = authHandler.generateToken({ id: user._id, username: user.username });
            res.send({
                token: token,
                user: { id: user._id, username: user.username }
            })
        } else {
            user.loginCount++;
            if (user.loginCount == 3) {
                user.loginCount = 0;
                user.lockTime = Date.now() + 3600 * 1000;
            }
            await user.save()
            res.status(404).send({
                message: "thong tin dang nhap khong dung"
            })
        }
    } catch (error) {
        res.status(404).send({
            message: error.message
        })
    }
})

router.post('/changepassword', authHandler.authenticate, [
    body('oldpassword').notEmpty().withMessage('Old password is required'),
    body('newpassword').isLength({ min: 6 }).withMessage('New password must be at least 6 characters long')
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/).withMessage('New password must contain at least one lowercase letter, one uppercase letter, and one number')
], async function (req, res, next) {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { oldpassword, newpassword } = req.body;
        const userId = req.user.id;
        const user = await userController.GetAnUserById(userId);

        if (!user) {
            return res.status(404).send({ message: 'User not found' });
        }

        if (!bcrypt.compareSync(oldpassword, user.password)) {
            return res.status(400).send({ message: 'Old password is incorrect' });
        }

        const hashedNewPassword = bcrypt.hashSync(newpassword, 10);
        user.password = hashedNewPassword;
        await user.save();

        res.send({ message: 'Password changed successfully' });
    } catch (error) {
        res.status(500).send({
            message: error.message
        })
    }
})

router.get('/me', authHandler.authenticate, async function (req, res, next) {
    try {
        const userId = req.user.id;
        const user = await userController.GetAnUserById(userId);

        if (!user) {
            return res.status(404).send({ message: 'User not found' });
        }

        // Trả về thông tin cá nhân, loại bỏ password và các trường nhạy cảm
        const userInfo = {
            id: user._id,
            username: user.username,
            email: user.email,
            fullName: user.fullName,
            avatarUrl: user.avatarUrl,
            status: user.status,
            role: user.role
        };

        res.send(userInfo);
    } catch (error) {
        res.status(500).send({
            message: error.message
        })
    }
})

module.exports = router