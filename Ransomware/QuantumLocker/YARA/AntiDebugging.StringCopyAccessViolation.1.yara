import "pe"

rule AntiDebugging_StringCopyAccessViolation_1 : M_B0002 A_T1622
{
    meta:
        author = "Malware Utkonos"
        organization = "ReversingLabs"
        date = "2023-03-28"
        description = "Detects an anti-debugging method which uses lstrcpyA to write a junk string to a read-only section raising an access violation"
        exemplar = "2fd8356abd42b19799aca857990a5f49631b02bd3253f80d96b5d27dcfd2f7c9"
        location = "0x1400040a6"
        api_documentation = "https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lstrcpya"
        mitre_att = "T1622"
        mitre_mbc = "B0002"
        minimum_yara = "4.3.0"
    strings:
        $op = {
            488d1d[4]    // lea   rbx, [rel junk_dest]
            488bcb       // mov   rcx, rbx  {junk_dest}
            488d15[4]    // lea   rdx, [rel junk_source]  {"eRgPKQSc"}
            ff15         // call  qword [rel lstrcpyA]
        }
    condition:
        for any i in (1..#op) : (
            not pe.sections[pe.section_index(pe.rva_to_offset(@op[i] + 7 - pe.sections[pe.section_index(@op[i])].raw_data_offset + pe.sections[pe.section_index(@op[i])].virtual_address + uint32(@op[i] + 3)))].characteristics & pe.SECTION_MEM_WRITE and
            for any imp in pe.import_details : (
                for any fun in imp.functions : (
                    fun.name == "lstrcpyA" and
                    @op[i] + !op[i] + 4 - pe.sections[pe.section_index(@op[i])].raw_data_offset + pe.sections[pe.section_index(@op[i])].virtual_address + uint32(@op[i] + !op[i]) == pe.import_rva(imp.library_name, "lstrcpyA")
                )
            )
        )
}