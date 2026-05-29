const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const supabase = require('../supabase')

// REGISTER
const register = async (req, res) => {
  try {
    const { username, email, password } = req.body

    // Check if user already exists
    const { data: existingUser } = await supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .single()

    if (existingUser) {
      return res.status(400).json({ 
        message: 'User already exists' 
      })
    }

    // Encrypt password
    const hashedPassword = await bcrypt.hash(password, 10)

    // Save user to database
    const { data: newUser, error } = await supabase
      .from('users')
      .insert([{
        username,
        email,
        password: hashedPassword
      }])
      .select()
      .single()

    if (error) {
      return res.status(500).json({ message: error.message })
    }

    // Create JWT token
    const token = jwt.sign(
      { id: newUser.id, email: newUser.email },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    )

    res.status(201).json({
      message: 'User registered successfully!',
      token,
      user: {
        id: newUser.id,
        username: newUser.username,
        email: newUser.email
      }
    })

  } catch (error) {
    res.status(500).json({ message: error.message })
  }
}

// LOGIN
const login = async (req, res) => {
  try {
    const { email, password } = req.body

    // Find user in database
    const { data: user } = await supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .single()

    if (!user) {
      return res.status(400).json({ 
        message: 'User not found' 
      })
    }

    // Check password
    const isPasswordValid = await bcrypt.compare(
      password, 
      user.password
    )

    if (!isPasswordValid) {
      return res.status(400).json({ 
        message: 'Wrong password' 
      })
    }

    // Create JWT token
    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    )

    res.status(200).json({
      message: 'Login successful!',
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email
      }
    })

  } catch (error) {
    res.status(500).json({ message: error.message })
  }
}

module.exports = { register, login }