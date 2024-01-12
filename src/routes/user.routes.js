import { Router } from "express";
import { loginUser, registerUser, logoutUser, refreshAccessToken } from "../controllers/user.controller.js";

const router = Router()
router.route("/register").post(
    upload.fields([
        {
            name: "avatar",
            maxCount: 1
        },
        {
            name: "coverImage",
            maxCount: 1
        }
    ]),
    registerUser)

    router.route("/logout").post(verifyJWT, logoutUser)
    router.route("/login").post(loginUser)
    router.route("/refresh-token").post(refreshAccessToken)

    
    export default router