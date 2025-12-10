import jenkins.model.*
import hudson.security.*

def env = System.getenv()

def username   = env['USER']
def password   = env['PASSWORD']
def fullName   = env['FULLNAME']

def instance = Jenkins.get()

def hudsonRealm = new HudsonPrivateSecurityRealm(false)
instance.setSecurityRealm(hudsonRealm)

def strategy = new FullControlOnceLoggedInAuthorizationStrategy()
strategy.setAllowAnonymousRead(false)
instance.setAuthorizationStrategy(strategy)

if (!hudsonRealm.getAllUsers().any { it.id == username }) {
    def user = hudsonRealm.createAccount(username, password)
    user.setFullName(fullName)
    user.save()
    println "User '${username}' created successfully."
} else {
    println "User '${username}' already exists."
}

def csrf = new hudson.security.csrf.DefaultCrumbIssuer(true)
instance.setCrumbIssuer(csrf)
instance.save()
println "User configuration completed."
