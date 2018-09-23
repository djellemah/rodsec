module Rodsec
  module ReadConfig
    # log_blk takes a tag and a string
    module_function def read_config config, rules, &log_blk
      config_dir = Pathname config
      rules_dir = Pathname(rules || config_dir + 'rules')

      # NOTE the first two config files MUST be loaded before the rules files
      config_rules = RuleSet.new
      config_rules.add_file config_dir + 'modsecurity.conf'
      config_rules.add_file config_dir + 'crs-setup.conf'

      # Now load the rules files
      rules_files = rules_dir.children.select{|p| p.to_s =~ /.*conf$/}.sort

      # merge rules files.
      rules_files.reduce config_rules do |ax, fn|
        # ruby 2.3.x syntax :-|
        begin
          log_blk&.call self.class, "loading rules file: #{fn}"
          rules = RuleSet.new tag: fn
          rules.add_file fn
          ax.merge rules
        rescue
          log_blk&.call $!.class, "error loading rules file: #{$!}"
          ax
        end
      end
    end
  end
end
