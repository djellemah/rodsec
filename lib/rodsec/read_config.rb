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

    # Hacky Workaround for the bug that's tickled by merging Rules.
    #
    # What we do is read all the files separately. Check each one to see that it
    # has no syntax errors. If that works, append the file contents to one giant
    # string containing all the rule files. When we've read all the rule files,
    # create one RuleSet from the combined string. That way we don't need to
    # merge rulesets.
    module_function def read_combined_config config, rules, &log_blk
      # part of the hacky workaround, so it's self-contained when we remove it.
      require 'stringio'
      config_dir = Pathname config
      rules_dir = Pathname(rules || config_dir + 'rules')

      # NOTE the first two config files MUST be loaded before the rules files
      files = [(config_dir + 'modsecurity.conf'), (config_dir + 'crs-setup.conf')]

      # Now add the rules files
      files.concat rules_dir.children.select{|p| p.to_s =~ /.*conf$/}.sort

      # merge rules files.
      combined_rules = files.each_with_object StringIO.new do |fn, sio|
        begin
          log_blk&.call self.class, "loading rules file: #{fn}"

          # syntax check rule set
          RuleSet.new.add_file fn.to_s

          File.open fn do |io| IO.copy_stream io, sio end
        rescue
          log_blk&.call $!.class, "error loading rules file: #{$!}"
        end
      end

      # make sure the rules can access their *.data files - we lose the file
      # location information when we use this approach.
      save_dir = Dir.pwd
      Dir.chdir rules_dir

      # add the combined rules
      log_blk&.call self.class, 'loading combined rules'
      p size: combined_rules.string.length
      rules = RuleSet.new
      rules.add combined_rules.string
      rules
    ensure
      # restore original directory
      save_dir and Dir.chdir save_dir
    end
  end
end
