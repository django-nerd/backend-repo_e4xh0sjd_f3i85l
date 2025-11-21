-- Aptly Professional Networking Platform - PostgreSQL Schema
-- All timestamps use TIMESTAMP WITH TIME ZONE
-- Extensions
CREATE EXTENSION IF NOT EXISTS pgcrypto; -- for gen_random_uuid, crypt
CREATE EXTENSION IF NOT EXISTS pg_trgm;  -- for text search acceleration
CREATE EXTENSION IF NOT EXISTS btree_gin;
CREATE EXTENSION IF NOT EXISTS citext;

-- Helper: Unified now() default
CREATE OR REPLACE FUNCTION tz_now() RETURNS timestamptz LANGUAGE sql IMMUTABLE AS $$ SELECT NOW()::timestamptz $$;

-- Schemas for organization
CREATE SCHEMA IF NOT EXISTS aptly;
CREATE SCHEMA IF NOT EXISTS security;
CREATE SCHEMA IF NOT EXISTS analytics;

-- Type Definitions
DO $$ BEGIN
  CREATE TYPE aptly.account_type AS ENUM ('free','premium','enterprise');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
  CREATE TYPE aptly.proficiency_level AS ENUM ('beginner','intermediate','advanced','expert');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
  CREATE TYPE aptly.post_type AS ENUM ('normal','ai_generated','shared');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
  CREATE TYPE aptly.visibility AS ENUM ('public','connections','private');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
  CREATE TYPE aptly.video_type AS ENUM ('skills','education','professional_journey','introduction');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
  CREATE TYPE aptly.video_quality AS ENUM ('720p','1080p','4k');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
  CREATE TYPE aptly.processing_status AS ENUM ('uploading','processing','transcoding','ready','failed');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
  CREATE TYPE aptly.ai_moderation_status AS ENUM ('pending','approved','flagged','rejected');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
  CREATE TYPE aptly.connection_status AS ENUM ('pending','accepted','rejected','cancelled');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
  CREATE TYPE aptly.connection_type AS ENUM ('normal','video');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
  CREATE TYPE aptly.payment_status AS ENUM ('pending','completed','failed','refunded','cancelled');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
  CREATE TYPE aptly.plan_type AS ENUM ('free','premium_monthly','premium_yearly','enterprise');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
  CREATE TYPE aptly.subscription_status AS ENUM ('active','cancelled','expired','suspended','trial');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
  CREATE TYPE aptly.billing_cycle AS ENUM ('monthly','yearly','lifetime');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- Security: Key management via pgcrypto - using pgp_sym_encrypt for sensitive fields
-- Assumes a server-side GUC aptly.encryption_key is set at connection time
CREATE OR REPLACE FUNCTION security.enc(v text) RETURNS bytea LANGUAGE sql AS $$
  SELECT pgp_sym_encrypt(v, current_setting('aptly.encryption_key'))
$$;
CREATE OR REPLACE FUNCTION security.dec(b bytea) RETURNS text LANGUAGE sql STABLE AS $$
  SELECT pgp_sym_decrypt(b, current_setting('aptly.encryption_key'))
$$;

-- Users
CREATE TABLE IF NOT EXISTS aptly.users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email_enc bytea NOT NULL UNIQUE,
  password_hash text NOT NULL,
  username citext UNIQUE,
  full_name text,
  profile_picture_url text,
  account_type aptly.account_type NOT NULL DEFAULT 'free',
  email_verified boolean NOT NULL DEFAULT false,
  phone_enc bytea,
  failed_login_attempts int NOT NULL DEFAULT 0,
  account_locked_until timestamptz,
  two_factor_enabled boolean NOT NULL DEFAULT false,
  two_factor_secret_enc bytea,
  last_login timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz
);

-- Functional indexes for encrypted fields
CREATE INDEX IF NOT EXISTS idx_users_email ON aptly.users ((security.dec(email_enc)));
CREATE INDEX IF NOT EXISTS idx_users_username ON aptly.users (username);
CREATE INDEX IF NOT EXISTS idx_users_account_type ON aptly.users (account_type);
CREATE INDEX IF NOT EXISTS idx_users_created_at ON aptly.users (created_at);

-- Password Reset Tokens
CREATE TABLE IF NOT EXISTS aptly.password_reset_tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid REFERENCES aptly.users(id) ON DELETE CASCADE,
  token_hash text UNIQUE NOT NULL,
  expires_at timestamptz NOT NULL,
  used_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_prt_user_id ON aptly.password_reset_tokens (user_id);
CREATE INDEX IF NOT EXISTS idx_prt_expires_at ON aptly.password_reset_tokens (expires_at);

-- User Sessions
CREATE TABLE IF NOT EXISTS aptly.user_sessions (
  session_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid REFERENCES aptly.users(id) ON DELETE CASCADE,
  ip_address_enc bytea,
  device_info jsonb,
  user_agent text,
  session_token_hash text UNIQUE NOT NULL,
  login_time timestamptz NOT NULL DEFAULT now(),
  logout_time timestamptz,
  last_activity timestamptz,
  is_active boolean NOT NULL DEFAULT true
);
CREATE INDEX IF NOT EXISTS idx_sessions_user_active ON aptly.user_sessions (user_id, is_active);
CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON aptly.user_sessions (session_token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_last_activity ON aptly.user_sessions (last_activity);

-- Profiles
CREATE TABLE IF NOT EXISTS aptly.user_profiles (
  user_id uuid PRIMARY KEY REFERENCES aptly.users(id) ON DELETE CASCADE,
  headline varchar(200),
  bio text,
  location text,
  website text,
  profile_completion_percentage int NOT NULL DEFAULT 0 CHECK (profile_completion_percentage BETWEEN 0 AND 100),
  is_public boolean NOT NULL DEFAULT true,
  profile_views_count int NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_profiles_completion ON aptly.user_profiles (profile_completion_percentage);
CREATE INDEX IF NOT EXISTS idx_profiles_location_public ON aptly.user_profiles (location) WHERE is_public;
CREATE INDEX IF NOT EXISTS idx_profiles_fts ON aptly.user_profiles USING GIN (to_tsvector('simple', coalesce(headline,'') || ' ' || coalesce(bio,'')));

-- Skills
CREATE TABLE IF NOT EXISTS aptly.skills (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  skill_name citext UNIQUE NOT NULL,
  category text,
  usage_count int NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_skills_name ON aptly.skills (skill_name);
CREATE INDEX IF NOT EXISTS idx_skills_category ON aptly.skills (category);
CREATE INDEX IF NOT EXISTS idx_skills_usage_desc ON aptly.skills (usage_count DESC);

CREATE TABLE IF NOT EXISTS aptly.user_skills (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES aptly.users(id) ON DELETE CASCADE,
  skill_id uuid NOT NULL REFERENCES aptly.skills(id) ON DELETE CASCADE,
  proficiency_level aptly.proficiency_level NOT NULL,
  years_experience int NOT NULL DEFAULT 0 CHECK (years_experience >= 0),
  endorsement_count int NOT NULL DEFAULT 0,
  added_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(user_id, skill_id)
);
CREATE INDEX IF NOT EXISTS idx_user_skills_user ON aptly.user_skills (user_id);
CREATE INDEX IF NOT EXISTS idx_user_skills_skill ON aptly.user_skills (skill_id);
CREATE INDEX IF NOT EXISTS idx_user_skills_prof ON aptly.user_skills (proficiency_level);

-- Education
CREATE TABLE IF NOT EXISTS aptly.education (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES aptly.users(id) ON DELETE CASCADE,
  institution text,
  degree text,
  field_of_study text,
  start_date date,
  end_date date CHECK (end_date IS NULL OR start_date IS NULL OR end_date > start_date),
  description text,
  is_current boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_edu_user ON aptly.education (user_id);
CREATE INDEX IF NOT EXISTS idx_edu_dates ON aptly.education (user_id, start_date DESC, end_date DESC);

-- Work Experience
CREATE TABLE IF NOT EXISTS aptly.work_experience (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES aptly.users(id) ON DELETE CASCADE,
  company text,
  position text NOT NULL,
  description text,
  start_date date NOT NULL,
  end_date date,
  is_current boolean NOT NULL DEFAULT false,
  location text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_work_user ON aptly.work_experience (user_id);
CREATE INDEX IF NOT EXISTS idx_work_dates ON aptly.work_experience (user_id, start_date DESC, end_date DESC);
CREATE INDEX IF NOT EXISTS idx_work_current ON aptly.work_experience (is_current) WHERE is_current;

-- Video Resumes
CREATE TABLE IF NOT EXISTS aptly.video_resumes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES aptly.users(id) ON DELETE CASCADE,
  video_type aptly.video_type NOT NULL,
  video_url_enc bytea NOT NULL,
  thumbnail_url_enc bytea NOT NULL,
  duration int,
  file_size bigint,
  title varchar(200),
  description text,
  video_format text,
  video_quality aptly.video_quality,
  view_count int NOT NULL DEFAULT 0,
  unique_view_count int NOT NULL DEFAULT 0,
  is_active boolean NOT NULL DEFAULT true,
  is_public boolean NOT NULL DEFAULT true,
  processing_status aptly.processing_status NOT NULL DEFAULT 'uploading',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz
);
CREATE INDEX IF NOT EXISTS idx_vres_user_active ON aptly.video_resumes (user_id, is_active);
CREATE INDEX IF NOT EXISTS idx_vres_type ON aptly.video_resumes (video_type);
CREATE INDEX IF NOT EXISTS idx_vres_views ON aptly.video_resumes (view_count DESC);
CREATE INDEX IF NOT EXISTS idx_vres_created ON aptly.video_resumes (created_at DESC);

-- Video Views (partitioned monthly)
CREATE TABLE IF NOT EXISTS aptly.video_views (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  video_id uuid NOT NULL REFERENCES aptly.video_resumes(id) ON DELETE CASCADE,
  viewer_user_id uuid REFERENCES aptly.users(id) ON DELETE SET NULL,
  viewed_at timestamptz NOT NULL DEFAULT now(),
  watch_duration int,
  completion_percentage int CHECK (completion_percentage BETWEEN 0 AND 100),
  ip_address_enc bytea
) PARTITION BY RANGE (viewed_at);

-- Template partition for current month
CREATE TABLE IF NOT EXISTS aptly.video_views_p2025_11 PARTITION OF aptly.video_views
  FOR VALUES FROM ('2025-11-01') TO ('2025-12-01');
CREATE INDEX IF NOT EXISTS idx_vviews_video_time ON aptly.video_views_p2025_11 (video_id, viewed_at DESC);
CREATE INDEX IF NOT EXISTS idx_vviews_viewer_time ON aptly.video_views_p2025_11 (viewer_user_id, viewed_at DESC);

-- Posts
CREATE TABLE IF NOT EXISTS aptly.posts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES aptly.users(id) ON DELETE CASCADE,
  content_text text,
  media_urls jsonb,
  post_type aptly.post_type NOT NULL DEFAULT 'normal',
  is_ai_assisted boolean NOT NULL DEFAULT false,
  visibility aptly.visibility NOT NULL DEFAULT 'public',
  like_count int NOT NULL DEFAULT 0,
  comment_count int NOT NULL DEFAULT 0,
  share_count int NOT NULL DEFAULT 0,
  view_count int NOT NULL DEFAULT 0,
  is_pinned boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  edited_at timestamptz,
  deleted_at timestamptz
);
CREATE INDEX IF NOT EXISTS idx_posts_user_created ON aptly.posts (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_posts_visibility_created ON aptly.posts (visibility, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_posts_engagement ON aptly.posts (like_count DESC, comment_count DESC, share_count DESC);
CREATE INDEX IF NOT EXISTS idx_posts_fts ON aptly.posts USING GIN (to_tsvector('english', coalesce(content_text,'')));
CREATE INDEX IF NOT EXISTS idx_posts_media_gin ON aptly.posts USING GIN (media_urls);

CREATE TABLE IF NOT EXISTS aptly.post_likes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  post_id uuid NOT NULL REFERENCES aptly.posts(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES aptly.users(id) ON DELETE CASCADE,
  liked_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(post_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_pl_post ON aptly.post_likes (post_id);
CREATE INDEX IF NOT EXISTS idx_pl_user_time ON aptly.post_likes (user_id, liked_at DESC);

CREATE TABLE IF NOT EXISTS aptly.post_comments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  post_id uuid NOT NULL REFERENCES aptly.posts(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES aptly.users(id) ON DELETE CASCADE,
  parent_comment_id uuid REFERENCES aptly.post_comments(id) ON DELETE SET NULL,
  comment_text text NOT NULL,
  like_count int NOT NULL DEFAULT 0,
  reply_count int NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz
);
CREATE INDEX IF NOT EXISTS idx_pc_post_time ON aptly.post_comments (post_id, created_at);
CREATE INDEX IF NOT EXISTS idx_pc_user ON aptly.post_comments (user_id);
CREATE INDEX IF NOT EXISTS idx_pc_parent ON aptly.post_comments (parent_comment_id) WHERE parent_comment_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS aptly.post_shares (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  post_id uuid NOT NULL REFERENCES aptly.posts(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES aptly.users(id) ON DELETE CASCADE,
  share_caption text,
  shared_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ps_post_time ON aptly.post_shares (post_id, shared_at DESC);
CREATE INDEX IF NOT EXISTS idx_ps_user_time ON aptly.post_shares (user_id, shared_at DESC);

-- Reels
DO $$ BEGIN
  CREATE TYPE aptly.reel_category AS ENUM ('professional_insight','career_tips','industry_news','personal_brand','skill_showcase','achievement','workplace_culture','general');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE TABLE IF NOT EXISTS aptly.reels (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES aptly.users(id) ON DELETE CASCADE,
  reel_category aptly.reel_category NOT NULL,
  video_url_enc bytea NOT NULL,
  thumbnail_url_enc bytea NOT NULL,
  title varchar(200),
  description text,
  hashtags text[],
  duration int,
  file_size bigint,
  video_format text,
  aspect_ratio text,
  video_quality aptly.video_quality,
  view_count int NOT NULL DEFAULT 0,
  unique_view_count int NOT NULL DEFAULT 0,
  like_count int NOT NULL DEFAULT 0,
  comment_count int NOT NULL DEFAULT 0,
  share_count int NOT NULL DEFAULT 0,
  save_count int NOT NULL DEFAULT 0,
  engagement_score numeric(10,4) NOT NULL DEFAULT 0,
  is_active boolean NOT NULL DEFAULT true,
  is_featured boolean NOT NULL DEFAULT false,
  visibility aptly.visibility NOT NULL DEFAULT 'public',
  allow_comments boolean NOT NULL DEFAULT true,
  allow_downloads boolean NOT NULL DEFAULT false,
  processing_status aptly.processing_status NOT NULL DEFAULT 'uploading',
  ai_moderation_status aptly.ai_moderation_status NOT NULL DEFAULT 'pending',
  ai_moderation_flags jsonb,
  is_original_content boolean NOT NULL DEFAULT true,
  copyright_status text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  published_at timestamptz,
  deleted_at timestamptz
);
CREATE INDEX IF NOT EXISTS idx_reels_user_created ON aptly.reels (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_reels_category_published ON aptly.reels (reel_category, published_at);
CREATE INDEX IF NOT EXISTS idx_reels_engagement ON aptly.reels (engagement_score DESC);
CREATE INDEX IF NOT EXISTS idx_reels_trending ON aptly.reels (created_at, view_count);
CREATE INDEX IF NOT EXISTS idx_reels_visibility ON aptly.reels (visibility);
CREATE INDEX IF NOT EXISTS idx_reels_featured ON aptly.reels (is_featured) WHERE is_featured;
CREATE INDEX IF NOT EXISTS idx_reels_processing ON aptly.reels (processing_status);
CREATE INDEX IF NOT EXISTS idx_reels_moderation ON aptly.reels (ai_moderation_status);
CREATE INDEX IF NOT EXISTS idx_reels_fts ON aptly.reels USING GIN (to_tsvector('english', coalesce(title,'') || ' ' || coalesce(description,'')));
CREATE INDEX IF NOT EXISTS idx_reels_hashtags ON aptly.reels USING GIN (hashtags);

-- Reel Analytics (partitioned monthly)
CREATE TABLE IF NOT EXISTS analytics.reel_analytics (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  reel_id uuid NOT NULL REFERENCES aptly.reels(id) ON DELETE CASCADE,
  date date NOT NULL,
  hour int NOT NULL CHECK (hour BETWEEN 0 AND 23),
  views int NOT NULL DEFAULT 0,
  unique_views int NOT NULL DEFAULT 0,
  likes int NOT NULL DEFAULT 0,
  comments int NOT NULL DEFAULT 0,
  shares int NOT NULL DEFAULT 0,
  saves int NOT NULL DEFAULT 0,
  average_watch_time int,
  completion_rate numeric,
  engagement_rate numeric,
  viewer_demographics jsonb,
  traffic_source jsonb,
  device_breakdown jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
) PARTITION BY RANGE (date);

CREATE TABLE IF NOT EXISTS analytics.reel_analytics_p2025_11 PARTITION OF analytics.reel_analytics
  FOR VALUES FROM ('2025-11-01') TO ('2025-12-01');
CREATE UNIQUE INDEX IF NOT EXISTS idx_ra_unique ON analytics.reel_analytics_p2025_11 (reel_id, date, hour);
CREATE INDEX IF NOT EXISTS idx_ra_reel_date ON analytics.reel_analytics_p2025_11 (reel_id, date DESC);
CREATE INDEX IF NOT EXISTS idx_ra_date ON analytics.reel_analytics_p2025_11 (date DESC);
CREATE INDEX IF NOT EXISTS idx_ra_engagement ON analytics.reel_analytics_p2025_11 (engagement_rate DESC);

-- Reel Views (partitioned weekly)
CREATE TABLE IF NOT EXISTS analytics.reel_views (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  reel_id uuid NOT NULL REFERENCES aptly.reels(id) ON DELETE CASCADE,
  viewer_user_id uuid REFERENCES aptly.users(id) ON DELETE SET NULL,
  session_id text,
  viewed_at timestamptz NOT NULL DEFAULT now(),
  watch_duration int,
  completion_percentage int CHECK (completion_percentage BETWEEN 0 AND 100),
  replayed boolean,
  replay_count int NOT NULL DEFAULT 0,
  ip_address_enc bytea,
  device_type text,
  device_os text,
  browser text,
  geo_location text,
  referral_source text,
  is_unique_view boolean NOT NULL DEFAULT true
) PARTITION BY RANGE (viewed_at);

CREATE TABLE IF NOT EXISTS analytics.reel_views_p2025_w47 PARTITION OF analytics.reel_views
  FOR VALUES FROM ('2025-11-17') TO ('2025-11-24');
CREATE INDEX IF NOT EXISTS idx_rv_reel_time ON analytics.reel_views_p2025_w47 (reel_id, viewed_at DESC);
CREATE INDEX IF NOT EXISTS idx_rv_viewer_time ON analytics.reel_views_p2025_w47 (viewer_user_id, viewed_at DESC);
CREATE INDEX IF NOT EXISTS idx_rv_completion ON analytics.reel_views_p2025_w47 (completion_percentage DESC);
CREATE INDEX IF NOT EXISTS idx_rv_session_reel ON analytics.reel_views_p2025_w47 (session_id, reel_id);

-- Saved Reels
CREATE TABLE IF NOT EXISTS aptly.saved_reels (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES aptly.users(id) ON DELETE CASCADE,
  reel_id uuid NOT NULL REFERENCES aptly.reels(id) ON DELETE CASCADE,
  collection_id uuid REFERENCES aptly.reel_collections(id) ON DELETE SET NULL,
  notes text,
  tags text[],
  saved_at timestamptz NOT NULL DEFAULT now(),
  last_viewed_at timestamptz,
  view_count int NOT NULL DEFAULT 0,
  UNIQUE(user_id, reel_id)
);
CREATE INDEX IF NOT EXISTS idx_sr_user_time ON aptly.saved_reels (user_id, saved_at DESC);
CREATE INDEX IF NOT EXISTS idx_sr_collection ON aptly.saved_reels (collection_id);
CREATE INDEX IF NOT EXISTS idx_sr_tags ON aptly.saved_reels USING GIN (tags);

-- Reel Collections
CREATE TABLE IF NOT EXISTS aptly.reel_collections (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES aptly.users(id) ON DELETE CASCADE,
  name varchar(100) NOT NULL,
  description text,
  cover_image_url text,
  is_private boolean NOT NULL DEFAULT true,
  reel_count int NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_rc_user_created ON aptly.reel_collections (user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_rc_public ON aptly.reel_collections (is_private) WHERE is_private = false;

-- Reel Drafts
CREATE TABLE IF NOT EXISTS aptly.reel_drafts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES aptly.users(id) ON DELETE CASCADE,
  reel_category aptly.reel_category,
  video_url_enc bytea,
  thumbnail_url_enc bytea,
  title text,
  description text,
  hashtags text[],
  visibility aptly.visibility,
  scheduled_publish_at timestamptz,
  draft_data_enc bytea,
  auto_save_enabled boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  last_edited_at timestamptz
);
CREATE INDEX IF NOT EXISTS idx_rd_user_updated ON aptly.reel_drafts (user_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_rd_scheduled ON aptly.reel_drafts (scheduled_publish_at) WHERE scheduled_publish_at IS NOT NULL;

-- Reel Transcripts
CREATE TABLE IF NOT EXISTS aptly.reel_transcripts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  reel_id uuid NOT NULL REFERENCES aptly.reels(id) ON DELETE CASCADE,
  transcript_text text,
  language text DEFAULT 'en',
  confidence_score numeric,
  timestamps jsonb,
  is_auto_generated boolean,
  is_reviewed boolean,
  reviewed_by_user_id uuid REFERENCES aptly.users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_rt_reel ON aptly.reel_transcripts (reel_id);
CREATE INDEX IF NOT EXISTS idx_rt_fts ON aptly.reel_transcripts USING GIN (to_tsvector('english', coalesce(transcript_text,'')));

-- Reel Hashtags
CREATE TABLE IF NOT EXISTS aptly.reel_hashtags (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  hashtag text,
  normalized_hashtag citext UNIQUE,
  usage_count int NOT NULL DEFAULT 1,
  trending_score numeric,
  category text,
  is_trending boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz
);
CREATE INDEX IF NOT EXISTS idx_rh_norm ON aptly.reel_hashtags (normalized_hashtag);
CREATE INDEX IF NOT EXISTS idx_rh_trending ON aptly.reel_hashtags (trending_score, usage_count) WHERE is_trending;
CREATE INDEX IF NOT EXISTS idx_rh_usage ON aptly.reel_hashtags (usage_count DESC);

-- Reel Recommendations (partitioned weekly)
CREATE TABLE IF NOT EXISTS analytics.reel_recommendations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES aptly.users(id) ON DELETE CASCADE,
  reel_id uuid NOT NULL REFERENCES aptly.reels(id) ON DELETE CASCADE,
  recommendation_score numeric(10,6) NOT NULL,
  recommendation_reason text,
  reason_details jsonb,
  shown_at timestamptz,
  clicked_at timestamptz,
  clicked boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz
) PARTITION BY RANGE (created_at);

CREATE TABLE IF NOT EXISTS analytics.reel_recommendations_p2025_w47 PARTITION OF analytics.reel_recommendations
  FOR VALUES FROM ('2025-11-17') TO ('2025-11-24');
CREATE INDEX IF NOT EXISTS idx_rr_user_score ON analytics.reel_recommendations_p2025_w47 (user_id, recommendation_score DESC, expires_at) WHERE shown_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_rr_reason_clicked ON analytics.reel_recommendations_p2025_w47 (recommendation_reason, clicked);

-- Reel Security Tables
CREATE TABLE IF NOT EXISTS aptly.reel_upload_rate_limits (
  user_id uuid PRIMARY KEY REFERENCES aptly.users(id) ON DELETE CASCADE,
  uploads_today int NOT NULL DEFAULT 0,
  uploads_this_month int NOT NULL DEFAULT 0,
  daily_limit int NOT NULL,
  monthly_limit int NOT NULL,
  last_upload_at timestamptz,
  reset_date date
);

CREATE TABLE IF NOT EXISTS aptly.reel_security_checks (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  reel_id uuid NOT NULL REFERENCES aptly.reels(id) ON DELETE CASCADE,
  check_type text,
  status text,
  check_details jsonb,
  checked_at timestamptz
);

CREATE TABLE IF NOT EXISTS aptly.reel_watermarks (
  reel_id uuid PRIMARY KEY REFERENCES aptly.reels(id) ON DELETE CASCADE,
  watermark_id text UNIQUE,
  watermark_type text,
  watermark_data_enc bytea,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Networking
CREATE TABLE IF NOT EXISTS aptly.connections (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  requester_user_id uuid NOT NULL REFERENCES aptly.users(id) ON DELETE CASCADE,
  receiver_user_id uuid NOT NULL REFERENCES aptly.users(id) ON DELETE CASCADE,
  connection_type aptly.connection_type NOT NULL DEFAULT 'normal',
  status aptly.connection_status NOT NULL,
  video_message_url_enc bytea,
  message_text text,
  requested_at timestamptz NOT NULL DEFAULT now(),
  responded_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (requester_user_id <> receiver_user_id),
  UNIQUE(requester_user_id, receiver_user_id)
);
CREATE INDEX IF NOT EXISTS idx_conn_requester_status ON aptly.connections (requester_user_id, status);
CREATE INDEX IF NOT EXISTS idx_conn_receiver_status ON aptly.connections (receiver_user_id, status);
CREATE INDEX IF NOT EXISTS idx_conn_status_time ON aptly.connections (status, requested_at);
CREATE INDEX IF NOT EXISTS idx_conn_type ON aptly.connections (connection_type);
CREATE INDEX IF NOT EXISTS idx_conn_mutual ON aptly.connections (requester_user_id, receiver_user_id, status);

CREATE TABLE IF NOT EXISTS aptly.following (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  follower_user_id uuid NOT NULL REFERENCES aptly.users(id) ON DELETE CASCADE,
  following_user_id uuid NOT NULL REFERENCES aptly.users(id) ON DELETE CASCADE,
  followed_at timestamptz NOT NULL DEFAULT now(),
  CHECK (follower_user_id <> following_user_id),
  UNIQUE(follower_user_id, following_user_id)
);
CREATE INDEX IF NOT EXISTS idx_follow_follower ON aptly.following (follower_user_id);
CREATE INDEX IF NOT EXISTS idx_follow_following ON aptly.following (following_user_id);
CREATE INDEX IF NOT EXISTS idx_follow_both ON aptly.following (follower_user_id, following_user_id);

CREATE TABLE IF NOT EXISTS aptly.blocked_users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  blocker_user_id uuid NOT NULL REFERENCES aptly.users(id) ON DELETE CASCADE,
  blocked_user_id uuid NOT NULL REFERENCES aptly.users(id) ON DELETE CASCADE,
  blocked_at timestamptz NOT NULL DEFAULT now(),
  reason text,
  CHECK (blocker_user_id <> blocked_user_id),
  UNIQUE(blocker_user_id, blocked_user_id)
);
CREATE INDEX IF NOT EXISTS idx_blocker ON aptly.blocked_users (blocker_user_id);
CREATE INDEX IF NOT EXISTS idx_blocked ON aptly.blocked_users (blocked_user_id);

-- AI Functionality
CREATE TABLE IF NOT EXISTS analytics.ai_usage_log (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES aptly.users(id) ON DELETE CASCADE,
  feature_type text NOT NULL,
  tokens_used int,
  cost numeric(10,4),
  request_data_enc bytea,
  response_data_enc bytea,
  execution_time_ms int,
  status text,
  error_message text,
  created_at timestamptz NOT NULL DEFAULT now()
) PARTITION BY RANGE (created_at);

CREATE TABLE IF NOT EXISTS analytics.ai_usage_log_p2025_11 PARTITION OF analytics.ai_usage_log
  FOR VALUES FROM ('2025-11-01') TO ('2025-12-01');
CREATE INDEX IF NOT EXISTS idx_ai_user_time ON analytics.ai_usage_log_p2025_11 (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_feature_time ON analytics.ai_usage_log_p2025_11 (feature_type, created_at);
CREATE INDEX IF NOT EXISTS idx_ai_status ON analytics.ai_usage_log_p2025_11 (status);

CREATE TABLE IF NOT EXISTS aptly.user_ai_credits (
  user_id uuid PRIMARY KEY REFERENCES aptly.users(id) ON DELETE CASCADE,
  credits_remaining int NOT NULL DEFAULT 0 CHECK (credits_remaining >= 0),
  credits_used int NOT NULL DEFAULT 0 CHECK (credits_used >= 0),
  credits_total int NOT NULL DEFAULT 0 CHECK (credits_total >= 0),
  last_recharged_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now(),
  subscription_type text,
  monthly_limit int
);
CREATE INDEX IF NOT EXISTS idx_ai_credits_remaining ON aptly.user_ai_credits (credits_remaining);

-- Subscriptions & Payments
CREATE TABLE IF NOT EXISTS aptly.subscriptions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES aptly.users(id) ON DELETE CASCADE,
  plan_type aptly.plan_type NOT NULL,
  status aptly.subscription_status NOT NULL,
  start_date timestamptz,
  end_date timestamptz,
  trial_end_date timestamptz,
  auto_renew boolean NOT NULL DEFAULT true,
  amount numeric(10,2),
  currency char(3) NOT NULL DEFAULT 'USD',
  billing_cycle aptly.billing_cycle NOT NULL,
  stripe_subscription_id_enc bytea,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_sub_user_status ON aptly.subscriptions (user_id, status);
CREATE INDEX IF NOT EXISTS idx_sub_status ON aptly.subscriptions (status);
CREATE INDEX IF NOT EXISTS idx_sub_end_active ON aptly.subscriptions (end_date) WHERE status = 'active';

CREATE TABLE IF NOT EXISTS aptly.payment_transactions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES aptly.users(id) ON DELETE CASCADE,
  subscription_id uuid REFERENCES aptly.subscriptions(id) ON DELETE SET NULL,
  amount numeric(10,2) NOT NULL,
  currency char(3) NOT NULL,
  payment_method text NOT NULL,
  transaction_id_enc bytea,
  stripe_payment_intent_id_enc bytea,
  status aptly.payment_status NOT NULL,
  failure_reason text,
  receipt_url text,
  created_at timestamptz NOT NULL DEFAULT now(),
  processed_at timestamptz
);
CREATE INDEX IF NOT EXISTS idx_pay_user_time ON aptly.payment_transactions (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_pay_status ON aptly.payment_transactions (status);
CREATE INDEX IF NOT EXISTS idx_pay_subscription ON aptly.payment_transactions (subscription_id);

-- Activity & Audit
CREATE TABLE IF NOT EXISTS analytics.user_activity_log (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid REFERENCES aptly.users(id) ON DELETE SET NULL,
  activity_type text NOT NULL,
  activity_details jsonb,
  ip_address_enc bytea,
  device_info jsonb,
  user_agent text,
  session_id uuid,
  geo_location text,
  created_at timestamptz NOT NULL DEFAULT now()
) PARTITION BY RANGE (created_at);

CREATE TABLE IF NOT EXISTS analytics.user_activity_log_p2025_11 PARTITION OF analytics.user_activity_log
  FOR VALUES FROM ('2025-11-01') TO ('2025-12-01');
CREATE INDEX IF NOT EXISTS idx_ua_user_time ON analytics.user_activity_log_p2025_11 (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ua_type_time ON analytics.user_activity_log_p2025_11 (activity_type, created_at);
CREATE INDEX IF NOT EXISTS idx_ua_time ON analytics.user_activity_log_p2025_11 (created_at DESC);

CREATE TABLE IF NOT EXISTS analytics.platform_analytics (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  metric_name text,
  metric_value numeric,
  metric_type text,
  dimensions jsonb,
  date date NOT NULL,
  hour int CHECK (hour BETWEEN 0 AND 23),
  category text,
  created_at timestamptz NOT NULL DEFAULT now()
) PARTITION BY RANGE (date);

CREATE TABLE IF NOT EXISTS analytics.platform_analytics_p2025_11 PARTITION OF analytics.platform_analytics
  FOR VALUES FROM ('2025-11-01') TO ('2025-12-01');
CREATE INDEX IF NOT EXISTS idx_pa_metric_date ON analytics.platform_analytics_p2025_11 (metric_name, date DESC);
CREATE INDEX IF NOT EXISTS idx_pa_date ON analytics.platform_analytics_p2025_11 (date DESC);
CREATE INDEX IF NOT EXISTS idx_pa_category_date ON analytics.platform_analytics_p2025_11 (category, date DESC);

CREATE TABLE IF NOT EXISTS security.security_audit_log (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid REFERENCES aptly.users(id) ON DELETE SET NULL,
  event_type text NOT NULL,
  severity text NOT NULL,
  event_details_enc bytea,
  ip_address inet,
  triggered_by text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_sal_user_time ON security.security_audit_log (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sal_severity_time ON security.security_audit_log (severity, created_at);
CREATE INDEX IF NOT EXISTS idx_sal_event_time ON security.security_audit_log (event_type, created_at);

-- Notifications
CREATE TABLE IF NOT EXISTS aptly.notifications (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES aptly.users(id) ON DELETE CASCADE,
  notification_type text NOT NULL,
  title varchar(200),
  message text,
  related_entity_type text,
  related_entity_id uuid,
  action_url text,
  is_read boolean NOT NULL DEFAULT false,
  is_archived boolean NOT NULL DEFAULT false,
  priority text NOT NULL DEFAULT 'medium',
  created_at timestamptz NOT NULL DEFAULT now(),
  read_at timestamptz,
  expires_at timestamptz
) PARTITION BY RANGE (created_at);

CREATE TABLE IF NOT EXISTS aptly.notifications_p2025_11 PARTITION OF aptly.notifications
  FOR VALUES FROM ('2025-11-01') TO ('2025-12-01');
CREATE INDEX IF NOT EXISTS idx_n_user_time ON aptly.notifications_p2025_11 (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_n_user_unread ON aptly.notifications_p2025_11 (user_id, is_read, created_at) WHERE NOT is_read;
CREATE INDEX IF NOT EXISTS idx_n_type ON aptly.notifications_p2025_11 (notification_type);
CREATE INDEX IF NOT EXISTS idx_n_priority_time ON aptly.notifications_p2025_11 (priority, created_at);

CREATE TABLE IF NOT EXISTS aptly.notification_preferences (
  user_id uuid PRIMARY KEY REFERENCES aptly.users(id) ON DELETE CASCADE,
  email_notifications boolean,
  push_notifications boolean,
  sms_notifications boolean,
  connection_requests boolean DEFAULT true,
  post_interactions boolean DEFAULT true,
  reel_interactions boolean DEFAULT true,
  profile_views boolean DEFAULT true,
  marketing_emails boolean DEFAULT false,
  weekly_digest boolean DEFAULT true,
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- Content Moderation
CREATE TABLE IF NOT EXISTS aptly.content_reports (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  reporter_user_id uuid REFERENCES aptly.users(id) ON DELETE SET NULL,
  reported_entity_type text NOT NULL,
  reported_entity_id uuid NOT NULL,
  report_reason text NOT NULL,
  report_details text,
  status text NOT NULL,
  reviewed_by_admin_id uuid,
  reviewed_at timestamptz,
  action_taken text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_cr_status_time ON aptly.content_reports (status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_cr_entity ON aptly.content_reports (reported_entity_type, reported_entity_id);

-- Materialized View: Trending Reels
CREATE MATERIALIZED VIEW IF NOT EXISTS analytics.trending_reels AS
SELECT 
  r.id, r.user_id, r.title, r.reel_category,
  r.view_count, r.engagement_score,
  (r.view_count * 0.4 + r.like_count * 1.5 + r.comment_count * 2.0 + r.share_count * 3.0)
  / NULLIF(EXTRACT(EPOCH FROM (now() - r.published_at))/3600, 0) AS trending_score
FROM aptly.reels r
WHERE r.is_active = true 
  AND r.visibility = 'public'
  AND r.published_at > now() - INTERVAL '7 days'
ORDER BY trending_score DESC
LIMIT 1000;
CREATE INDEX IF NOT EXISTS idx_trending_score ON analytics.trending_reels(trending_score DESC);

-- Access helpers
CREATE OR REPLACE FUNCTION security.are_connected(u1 uuid, u2 uuid)
RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT EXISTS (
    SELECT 1 FROM aptly.connections c
    WHERE ((c.requester_user_id = u1 AND c.receiver_user_id = u2)
        OR (c.requester_user_id = u2 AND c.receiver_user_id = u1))
      AND c.status = 'accepted'
  );
$$;

CREATE OR REPLACE FUNCTION security.can_view_reel(reel_uuid uuid, viewer_uuid uuid)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
  RETURN EXISTS (
    SELECT 1 FROM aptly.reels r
    WHERE r.id = reel_uuid AND r.deleted_at IS NULL
    AND (r.visibility = 'public'
      OR (r.visibility = 'connections' AND security.are_connected(r.user_id, viewer_uuid))
      OR (r.visibility = 'private' AND r.user_id = viewer_uuid))
  );
END;$$;

-- RLS enable and policies
ALTER TABLE aptly.users ENABLE ROW LEVEL SECURITY;
CREATE POLICY users_self ON aptly.users USING (id = current_setting('app.current_user')::uuid) WITH CHECK (id = current_setting('app.current_user')::uuid);

ALTER TABLE aptly.user_profiles ENABLE ROW LEVEL SECURITY;
CREATE POLICY profiles_public_read ON aptly.user_profiles FOR SELECT USING (is_public OR user_id = current_setting('app.current_user')::uuid);
CREATE POLICY profiles_self_modify ON aptly.user_profiles FOR UPDATE, DELETE USING (user_id = current_setting('app.current_user')::uuid) WITH CHECK (user_id = current_setting('app.current_user')::uuid);
CREATE POLICY profiles_self_insert ON aptly.user_profiles FOR INSERT WITH CHECK (user_id = current_setting('app.current_user')::uuid);

ALTER TABLE aptly.user_sessions ENABLE ROW LEVEL SECURITY;
CREATE POLICY sessions_self ON aptly.user_sessions USING (user_id = current_setting('app.current_user')::uuid) WITH CHECK (user_id = current_setting('app.current_user')::uuid);

ALTER TABLE aptly.password_reset_tokens ENABLE ROW LEVEL SECURITY;
CREATE POLICY prt_self ON aptly.password_reset_tokens USING (user_id = current_setting('app.current_user')::uuid);

ALTER TABLE aptly.posts ENABLE ROW LEVEL SECURITY;
CREATE POLICY posts_vis_read ON aptly.posts FOR SELECT USING (
  visibility = 'public' OR user_id = current_setting('app.current_user')::uuid
);
CREATE POLICY posts_self_write ON aptly.posts FOR INSERT, UPDATE, DELETE USING (user_id = current_setting('app.current_user')::uuid) WITH CHECK (user_id = current_setting('app.current_user')::uuid);

ALTER TABLE aptly.post_comments ENABLE ROW LEVEL SECURITY;
CREATE POLICY pc_read ON aptly.post_comments FOR SELECT USING (true);
CREATE POLICY pc_write_self ON aptly.post_comments FOR INSERT, UPDATE, DELETE USING (user_id = current_setting('app.current_user')::uuid) WITH CHECK (user_id = current_setting('app.current_user')::uuid);

ALTER TABLE aptly.post_likes ENABLE ROW LEVEL SECURITY;
CREATE POLICY pl_self ON aptly.post_likes USING (user_id = current_setting('app.current_user')::uuid) WITH CHECK (user_id = current_setting('app.current_user')::uuid);

ALTER TABLE aptly.reels ENABLE ROW LEVEL SECURITY;
CREATE POLICY reels_read_vis ON aptly.reels FOR SELECT USING (
  visibility = 'public' OR user_id = current_setting('app.current_user')::uuid OR (visibility = 'connections' AND security.are_connected(user_id, current_setting('app.current_user')::uuid))
);
CREATE POLICY reels_self_write ON aptly.reels FOR INSERT, UPDATE, DELETE USING (user_id = current_setting('app.current_user')::uuid) WITH CHECK (user_id = current_setting('app.current_user')::uuid);

ALTER TABLE analytics.reel_analytics ENABLE ROW LEVEL SECURITY;
CREATE POLICY ra_owner_read ON analytics.reel_analytics FOR SELECT USING (
  EXISTS (SELECT 1 FROM aptly.reels r WHERE r.id = reel_id AND r.user_id = current_setting('app.current_user')::uuid)
);

ALTER TABLE analytics.reel_views ENABLE ROW LEVEL SECURITY;
CREATE POLICY rv_owner_or_self ON analytics.reel_views FOR SELECT USING (
  EXISTS (SELECT 1 FROM aptly.reels r WHERE r.id = reel_id AND r.user_id = current_setting('app.current_user')::uuid)
  OR viewer_user_id = current_setting('app.current_user')::uuid
);

ALTER TABLE aptly.saved_reels ENABLE ROW LEVEL SECURITY;
CREATE POLICY sr_self ON aptly.saved_reels USING (user_id = current_setting('app.current_user')::uuid) WITH CHECK (user_id = current_setting('app.current_user')::uuid);

ALTER TABLE aptly.reel_collections ENABLE ROW LEVEL SECURITY;
CREATE POLICY rc_self ON aptly.reel_collections USING (user_id = current_setting('app.current_user')::uuid) WITH CHECK (user_id = current_setting('app.current_user')::uuid);

ALTER TABLE aptly.reel_drafts ENABLE ROW LEVEL SECURITY;
CREATE POLICY rd_self ON aptly.reel_drafts USING (user_id = current_setting('app.current_user')::uuid) WITH CHECK (user_id = current_setting('app.current_user')::uuid);

ALTER TABLE aptly.reel_transcripts ENABLE ROW LEVEL SECURITY;
CREATE POLICY rt_vis ON aptly.reel_transcripts USING (
  EXISTS (
    SELECT 1 FROM aptly.reels r WHERE r.id = reel_id AND (
      r.visibility = 'public' OR r.user_id = current_setting('app.current_user')::uuid OR (r.visibility = 'connections' AND security.are_connected(r.user_id, current_setting('app.current_user')::uuid))
    )
  )
);

ALTER TABLE aptly.connections ENABLE ROW LEVEL SECURITY;
CREATE POLICY conn_involving_self ON aptly.connections USING (
  requester_user_id = current_setting('app.current_user')::uuid OR receiver_user_id = current_setting('app.current_user')::uuid
);

ALTER TABLE aptly.following ENABLE ROW LEVEL SECURITY;
CREATE POLICY following_self ON aptly.following USING (
  follower_user_id = current_setting('app.current_user')::uuid OR following_user_id = current_setting('app.current_user')::uuid
);

ALTER TABLE aptly.blocked_users ENABLE ROW LEVEL SECURITY;
CREATE POLICY blocked_self ON aptly.blocked_users USING (blocker_user_id = current_setting('app.current_user')::uuid);

ALTER TABLE analytics.ai_usage_log ENABLE ROW LEVEL SECURITY;
CREATE POLICY ai_self ON analytics.ai_usage_log USING (user_id = current_setting('app.current_user')::uuid);

ALTER TABLE aptly.user_ai_credits ENABLE ROW LEVEL SECURITY;
CREATE POLICY ai_credits_self ON aptly.user_ai_credits USING (user_id = current_setting('app.current_user')::uuid) WITH CHECK (user_id = current_setting('app.current_user')::uuid);

ALTER TABLE aptly.subscriptions ENABLE ROW LEVEL SECURITY;
CREATE POLICY sub_self ON aptly.subscriptions USING (user_id = current_setting('app.current_user')::uuid) WITH CHECK (user_id = current_setting('app.current_user')::uuid);

ALTER TABLE aptly.payment_transactions ENABLE ROW LEVEL SECURITY;
CREATE POLICY pay_self ON aptly.payment_transactions USING (user_id = current_setting('app.current_user')::uuid);

ALTER TABLE analytics.user_activity_log ENABLE ROW LEVEL SECURITY;
CREATE POLICY ua_self_or_admin ON analytics.user_activity_log USING (
  user_id = current_setting('app.current_user')::uuid OR current_setting('app.role', true) = 'admin'
);

ALTER TABLE aptly.notifications ENABLE ROW LEVEL SECURITY;
CREATE POLICY n_self ON aptly.notifications USING (user_id = current_setting('app.current_user')::uuid);

ALTER TABLE aptly.notification_preferences ENABLE ROW LEVEL SECURITY;
CREATE POLICY np_self ON aptly.notification_preferences USING (user_id = current_setting('app.current_user')::uuid) WITH CHECK (user_id = current_setting('app.current_user')::uuid);

ALTER TABLE aptly.content_reports ENABLE ROW LEVEL SECURITY;
CREATE POLICY cr_reporter_or_admin ON aptly.content_reports USING (
  reporter_user_id = current_setting('app.current_user')::uuid OR current_setting('app.role', true) = 'admin'
);

-- Triggers: update timestamps
CREATE OR REPLACE FUNCTION security.set_updated_at() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;$$;

DROP TRIGGER IF EXISTS trg_users_updated ON aptly.users;
CREATE TRIGGER trg_users_updated BEFORE UPDATE ON aptly.users FOR EACH ROW EXECUTE FUNCTION security.set_updated_at();
DROP TRIGGER IF EXISTS trg_profiles_updated ON aptly.user_profiles;
CREATE TRIGGER trg_profiles_updated BEFORE UPDATE ON aptly.user_profiles FOR EACH ROW EXECUTE FUNCTION security.set_updated_at();
DROP TRIGGER IF EXISTS trg_reels_updated ON aptly.reels;
CREATE TRIGGER trg_reels_updated BEFORE UPDATE ON aptly.reels FOR EACH ROW EXECUTE FUNCTION security.set_updated_at();

-- Triggers: engagement_score recalculation
CREATE OR REPLACE FUNCTION analytics.update_reel_engagement() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.engagement_score := COALESCE(NEW.view_count,0)*0.4 + COALESCE(NEW.like_count,0)*1.5 + COALESCE(NEW.comment_count,0)*2.0 + COALESCE(NEW.share_count,0)*3.0 + COALESCE(NEW.save_count,0)*1.0;
  RETURN NEW;
END;$$;
DROP TRIGGER IF EXISTS trg_reels_engagement ON aptly.reels;
CREATE TRIGGER trg_reels_engagement BEFORE INSERT OR UPDATE ON aptly.reels FOR EACH ROW EXECUTE FUNCTION analytics.update_reel_engagement();

-- Triggers: auto-delete old drafts (> 30 days)
CREATE OR REPLACE FUNCTION aptly.cleanup_old_drafts() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  DELETE FROM aptly.reel_drafts WHERE created_at < now() - INTERVAL '30 days';
  RETURN NULL;
END;$$;
DROP TRIGGER IF EXISTS trg_cleanup_drafts ON aptly.reel_drafts;
CREATE TRIGGER trg_cleanup_drafts AFTER INSERT ON aptly.reel_drafts EXECUTE FUNCTION aptly.cleanup_old_drafts();

-- Prepared statements (examples)
PREPARE get_user_by_email(text) AS SELECT * FROM aptly.users WHERE security.dec(email_enc) = $1;
PREPARE insert_user(text, text) AS INSERT INTO aptly.users (email_enc, password_hash) VALUES (security.enc($1), $2) RETURNING id;

-- Connection pooling recommendations (configure in app): max_connections=100, statement_timeout=30000
-- Redis caching: to be configured in application layer for trending_reels (15m) and feeds (5m)

