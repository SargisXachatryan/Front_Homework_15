"use server"

import { OptionalUser } from "./types"
import { nanoid } from "nanoid"
import bcrypt from "bcrypt"
import { addUser, getAllUsers } from "./api"
import { redirect } from "next/navigation"

export const handleSignup = async (prev: unknown, data: FormData) => {
  const name = (data.get("name") as string).trim()
  const surname = (data.get("surname") as string).trim()
  const login = (data.get("login") as string).trim()
  const password = (data.get("password") as string).trim()

  if (!name || !surname || !login || !password) {
    return {
      message: "Please fill all the fields"
    }
  }

  const users = await getAllUsers()
  const isDuplicate = users.some(user => user.login === login)
  if (isDuplicate) {
    return {
      message: "A user with the same login already exists"
    }
  }

  const legalPassword = /^[a-zA-Z0-9!@#$%^&*]{6,16}$/

  if (!legalPassword.test(password)) {
    return {
      message: "Password should contain at least one number and one special character"
    }
  }

  const user: OptionalUser = {
    id: nanoid(),
    name: name,
    surname: surname,
    login: login
  }

  user.password = await bcrypt.hash(password, 10)
  await addUser(user)

  redirect("/login")
}

export const handleLogin = async (prev: unknown, data: FormData) => {
  const login = (data.get("login") as string).trim()
  const password = (data.get("password") as string).trim()

  if (!login || !password) {
    return {
      message: "Please fill all the fields"
    }
  }

  const users = await getAllUsers()
  const user = users.find(user => user.login === login)

  if (!user) {
    return {
      message: `A user with the login <${login}> doesn't exist`
    }
  }

  const legalPassword = await bcrypt.compare(password, user.password)

  if (!legalPassword) {
    return {
      message: "The password doesn't match"
    }
  }

  redirect("/profile")
}
