export MOLECULE_GLOB := extensions/molecule/*/molecule.yml
MOLECULE_SCENARIO ?= invoice_portal

.PHONY: molecule test converge destroy
molecule:
	molecule test -s $(MOLECULE_SCENARIO)

test: molecule

converge:
	molecule converge -s $(MOLECULE_SCENARIO)

destroy:
	molecule destroy -s $(MOLECULE_SCENARIO)
