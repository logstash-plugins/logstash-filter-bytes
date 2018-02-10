Gem::Specification.new do |s|
  s.name          = 'logstash-filter-bytes'
  s.version       = '0.1.0'
  s.licenses      = ['Apache-2.0']
  s.summary       = "This filter parses strings representing computer storage sizes into numeric bytes"
  s.description   = 'This filter parses strings representing computer storage sizes (e.g. "123 MB" or "6.3GB") into numeric bytes (12'
  s.homepage      = 'https://github.com/ycombinator/logstash-filter-bytes'
  s.authors       = ['Shaunak Kashyap']
  s.email         = 'ycombinator@gmail.com'
  s.require_paths = ['lib']

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','CONTRIBUTORS','Gemfile','LICENSE','NOTICE.TXT']
   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "filter" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core-plugin-api", "~> 2.0"
  s.add_development_dependency 'logstash-devutils'
end