# Use official Ruby image
FROM ruby:3.1.0

# Set working directory
WORKDIR /app

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy Gemfile and install gems
COPY Gemfile ./
RUN gem install bundler && \
    bundle install

# Copy the rest of the application
COPY . .

# Build the Jekyll site
RUN bundle exec jekyll build --baseurl="/kang-build-github-io"

# Expose port for serving (optional)
EXPOSE 4000

# Command to serve the site (can be overridden)
CMD ["bundle", "exec", "jekyll", "serve", "--host", "0.0.0.0"]
