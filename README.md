# Game Keys Store - Vercel Deployment

A beautiful, modern game keys store with PostgreSQL database, deployed on Vercel.

## Features

- 🎮 Product catalog with game keys
- 👥 User registration and authentication
- 💰 Wallet system with UPI top-ups
- 🔑 Encrypted product keys (Fernet)
- 📊 Admin dashboard
- ✨ Stunning modern UI with animations

## Prerequisites

1. **Vercel Account** - Sign up at [vercel.com](https://vercel.com)
2. **PostgreSQL Database** - You need a PostgreSQL database (recommended: Neon, Supabase, or Railway)
3. **GitHub Repository** - Push your code to GitHub

## Local Development

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your values
```

3. Run locally:
```bash
python app.py
```

## Deployment to Vercel

### Step 1: Get a PostgreSQL Database

**Option A: Neon (Free)**
1. Go to [neon.tech](https://neon.tech)
2. Create a free account
3. Create a new project
4. Copy the connection string (DATABASE_URL)

**Option B: Supabase (Free)**
1. Go to [supabase.com](https://supabase.com)
2. Create a free account
3. Create a new project
4. Go to Settings > Database
5. Copy the connection string

**Option C: Railway (Free tier available)**
1. Go to [railway.app](https://railway.app)
2. Create a new PostgreSQL database
3. Copy the connection string

### Step 2: Generate Secrets

Run these commands to generate your secrets:

```bash
# Generate SECRET_KEY
python -c "import secrets; print(secrets.token_hex(32))"

# Generate KEY_ENC_SECRET
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

### Step 3: Push to GitHub

```bash
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/your-repo.git
git push -u origin main
```

### Step 4: Deploy to Vercel

1. Go to [vercel.com](https://vercel.com)
2. Click "Add New Project"
3. Import your GitHub repository
4. Configure environment variables:
   - `SECRET_KEY`: Your generated secret key
   - `KEY_ENC_SECRET`: Your generated Fernet key
   - `ADMIN_EMAIL`: admin@example.com (or your email)
   - `ADMIN_PASSWORD`: Your strong password
   - `DATABASE_URL`: Your PostgreSQL connection string

5. Click "Deploy"

### Step 5: Configure Environment Variables in Vercel

After deployment, go to:
1. Your project in Vercel
2. Settings > Environment Variables
3. Add all the variables from Step 4
4. Redeploy

## Important Notes

### File Uploads
Vercel's file system is ephemeral. Uploaded images will be lost on redeployment. For production:
- Use a cloud storage service (AWS S3, Cloudinary, etc.)
- Modify the `save_image` function to upload to cloud storage

### Session Storage
Vercel's serverless functions don't persist sessions. For production:
- Use Redis or another session store
- Or use Vercel's Edge Config

### Database Connection Pooling
The app uses connection pooling for PostgreSQL. This is configured for serverless environments.

## Admin Credentials

After first deployment:
- Email: The email you set in `ADMIN_EMAIL`
- Password: The password you set in `ADMIN_PASSWORD`

## Troubleshooting

### Database Connection Errors
- Verify your `DATABASE_URL` is correct
- Make sure your database allows Vercel's IP addresses
- Check if your database has connection limits

### Import Errors
- Make sure all dependencies are in `requirements.txt`
- Vercel will automatically install them

### Environment Variables Not Working
- Variables must be set in Vercel dashboard
- Redeploy after adding variables
- Check variable names match exactly

## Support

For issues with:
- **Vercel**: [Vercel Docs](https://vercel.com/docs)
- **PostgreSQL**: Check your database provider's docs
- **This App**: Check the code comments or create an issue

## License

This is a reference implementation. Modify as needed for your use case.
