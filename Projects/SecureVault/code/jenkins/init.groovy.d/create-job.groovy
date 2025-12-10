import jenkins.model.*
import hudson.model.*

def jobName = "run-tests"
def jobDir = new File("/var/jenkins_home/jobs/" + jobName)

if (!Jenkins.instance.getItemByFullName(jobName)) {
    def configFile = new File(jobDir, "config.xml")
    if (configFile.exists()) {
        def stream = new FileInputStream(configFile)
        def job = Jenkins.instance.createProjectFromXML(jobName, stream)
        println "Job $jobName created successfully."
    }
}
