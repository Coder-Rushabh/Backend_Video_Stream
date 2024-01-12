import { Router } from "express";
import { loginUser, registerUser, logoutUser } from "../controllers/user.controller.js";

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

    
    export default router