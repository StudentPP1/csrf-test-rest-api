package github.studentpp1.csrftest.response;


public class UserResponse {
    private String username;
    private String name;

    private UserResponse(Builder builder) {
        this.username = builder.username;
        this.name = builder.name;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String username;
        private String name;

        public Builder username(String username) {
            this.username = username;
            return this;
        }

        public Builder name(String name) {
            this.name = name;
            return this;
        }

        public UserResponse build() {
            return new UserResponse(this);
        }
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
