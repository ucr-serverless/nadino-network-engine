#!/bin/bash

CPU_SHM_MGR=(0)
CPU_GATEWAY=(0 1 2 3 4 5)
CPU_NF=(6 7 8 9 20 21 22 23 24 25 26 27 28 29)

if [ ${EUID} -ne 0 ]
then
	echo "${0}: Permission denied" 1>&2
	exit 1
fi

if [ ${RTE_RING} ] && [ ${RTE_RING} -eq 1 ]
then
	io=rte_ring
else
	io=sk_msg
fi

print_usage()
{
	echo "usage: ${0} < shm_mgr CFG_FILE | gateway CFG_FILE | cpu_gateway CFG_FILE | nf NF_ID  | nf_tenant NF_ID TENANT_ID>" 1>&2
}

shm_mgr()
{
	if ! [ ${1} ]
	then
		print_usage
		exit 1
	fi

	exec build/shm_mgr_${io} \
		-l ${CPU_SHM_MGR[0]} \
		--file-prefix=spright \
		--proc-type=primary \
		--no-telemetry \
		--no-pci \
		-- \
		${1}
}

gateway()
{
	if ! [ ${1} ]
	then
		print_usage
		exit 1
	fi
	exec build/gateway_${io} \
		-l ${CPU_GATEWAY[0]},${CPU_GATEWAY[1]},${CPU_GATEWAY[2]},${CPU_GATEWAY[3]},${CPU_GATEWAY[4]},${CPU_GATEWAY[5]} \
		--main-lcore=${CPU_GATEWAY[0]} \
		--file-prefix=spright \
		--proc-type=primary \
		--no-telemetry \
		--no-pci \
        -- \
        ${1}
}

cpu_gateway()
{
	if ! [ ${1} ]
	then
		print_usage
		exit 1
	fi
	exec build/gateway_${io} \
		-l ${CPU_GATEWAY[0]},${CPU_GATEWAY[1]},${CPU_GATEWAY[2]},${CPU_GATEWAY[3]},${CPU_GATEWAY[4]},${CPU_GATEWAY[5]} \
		--main-lcore=${CPU_GATEWAY[0]} \
		--file-prefix=spright \
		--proc-type=secondary \
		--no-telemetry \
		--no-pci \
        -- \
        ${1}
}
nf()
{
	if ! [ ${1} ]
	then
		print_usage
		exit 1
	fi

	if [ ${GO_NF} ] && [ ${GO_NF} -eq 1 ]
	then
		go="go_"
	else
		go=""
	fi

	exec build/${go}nf_${io} \
		-l ${CPU_NF[$((${1} - 1))]} \
		--file-prefix=spright \
		--proc-type=secondary \
		--no-telemetry \
		--no-pci \
		-- \
		${1}
}

nf_tenant()
{
	if ! [ ${1} ]
	then
		print_usage
		exit 1
	fi

	if ! [ ${2} ]
	then
		print_usage
		exit 1
	fi

	if [ ${GO_NF} ] && [ ${GO_NF} -eq 1 ]
	then
		go="go_"
	else
		go=""
	fi

	exec build/${go}nf_${io} \
		-l ${CPU_NF[$((${1} - 1))]} \
		--file-prefix=spright \
		--proc-type=secondary \
		--no-telemetry \
		--no-pci \
		-- \
		${1} \
        ${2}
}
adservice()
{
	if ! [ ${1} ]
	then
		print_usage
		exit 1
	fi

	if [ ${GO_NF} ] && [ ${GO_NF} -eq 1 ]
	then
		go="go_"
	else
		go=""
	fi

	exec build/${go}nf_adservice_${io} \
		-l ${CPU_NF[$((${1} - 1))]} \
		--file-prefix=spright \
		--proc-type=secondary \
		--no-telemetry \
		--no-pci \
		-- \
		${1}
}

currencyservice()
{
	if ! [ ${1} ]
	then
		print_usage
		exit 1
	fi

	if [ ${GO_NF} ] && [ ${GO_NF} -eq 1 ]
	then
		go="go_"
	else
		go=""
	fi

	exec build/${go}nf_currencyservice_${io} \
		-l ${CPU_NF[$((${1} - 1))]} \
		--file-prefix=spright \
		--proc-type=secondary \
		--no-telemetry \
		--no-pci \
		-- \
		${1}
}

emailservice()
{
	if ! [ ${1} ]
	then
		print_usage
		exit 1
	fi

	if [ ${GO_NF} ] && [ ${GO_NF} -eq 1 ]
	then
		go="go_"
	else
		go=""
	fi

	exec build/${go}nf_emailservice_${io} \
		-l ${CPU_NF[$((${1} - 1))]} \
		--file-prefix=spright \
		--proc-type=secondary \
		--no-telemetry \
		--no-pci \
		-- \
		${1}
}

paymentservice()
{
	if ! [ ${1} ]
	then
		print_usage
		exit 1
	fi

	if [ ${GO_NF} ] && [ ${GO_NF} -eq 1 ]
	then
		go="go_"
	else
		go=""
	fi

	exec build/${go}nf_paymentservice_${io} \
		-l ${CPU_NF[$((${1} - 1))]} \
		--file-prefix=spright \
		--proc-type=secondary \
		--no-telemetry \
		--no-pci \
		-- \
		${1}
}

shippingservice()
{
	if ! [ ${1} ]
	then
		print_usage
		exit 1
	fi

	if [ ${GO_NF} ] && [ ${GO_NF} -eq 1 ]
	then
		go="go_"
	else
		go=""
	fi

	exec build/${go}nf_shippingservice_${io} \
		-l ${CPU_NF[$((${1} - 1))]} \
		--file-prefix=spright \
		--proc-type=secondary \
		--no-telemetry \
		--no-pci \
		-- \
		${1}
}

productcatalogservice()
{
	if ! [ ${1} ]
	then
		print_usage
		exit 1
	fi

	if [ ${GO_NF} ] && [ ${GO_NF} -eq 1 ]
	then
		go="go_"
	else
		go=""
	fi

	exec build/${go}nf_productcatalogservice_${io} \
		-l ${CPU_NF[$((${1} - 1))]} \
		--file-prefix=spright \
		--proc-type=secondary \
		--no-telemetry \
		--no-pci \
		-- \
		${1}
}

cartservice()
{
	if ! [ ${1} ]
	then
		print_usage
		exit 1
	fi

	if [ ${GO_NF} ] && [ ${GO_NF} -eq 1 ]
	then
		go="go_"
	else
		go=""
	fi

	exec build/${go}nf_cartservice_${io} \
		-l ${CPU_NF[$((${1} - 1))]} \
		--file-prefix=spright \
		--proc-type=secondary \
		--no-telemetry \
		--no-pci \
		-- \
		${1}
}

recommendationservice()
{
	if ! [ ${1} ]
	then
		print_usage
		exit 1
	fi

	if [ ${GO_NF} ] && [ ${GO_NF} -eq 1 ]
	then
		go="go_"
	else
		go=""
	fi

	exec build/${go}nf_recommendationservice_${io} \
		-l ${CPU_NF[$((${1} - 1))]} \
		--file-prefix=spright \
		--proc-type=secondary \
		--no-telemetry \
		--no-pci \
		-- \
		${1}
}

frontendservice()
{
	if ! [ ${1} ]
	then
		print_usage
		exit 1
	fi

	if [ ${GO_NF} ] && [ ${GO_NF} -eq 1 ]
	then
		go="go_"
	else
		go=""
	fi

	exec build/${go}nf_frontendservice_${io} \
		-l ${CPU_NF[$((${1} - 1))]} \
		--file-prefix=spright \
		--proc-type=secondary \
		--no-telemetry \
		--no-pci \
		-- \
		${1}
}

checkoutservice()
{
	if ! [ ${1} ]
	then
		print_usage
		exit 1
	fi

	if [ ${GO_NF} ] && [ ${GO_NF} -eq 1 ]
	then
		go="go_"
	else
		go=""
	fi

	exec build/${go}nf_checkoutservice_${io} \
		-l ${CPU_NF[$((${1} - 1))]} \
		--file-prefix=spright \
		--proc-type=secondary \
		--no-telemetry \
		--no-pci \
		-- \
		${1}
}


sockmap_manager()
{
    exec build/sockmap_manager

}

case ${1} in
	"shm_mgr" )
		shm_mgr ${2}
	;;

    "sockmap_manager" )
        sockmap_manager
    ;;

	"gateway" )
		gateway ${2}
	;;

	"cpu_gateway" )
		cpu_gateway ${2}
	;;
	"nf" )
		nf ${2}
	;;

	"nf_tenant" )
		nf_tenant ${2} ${3}
	;;
	"adservice" )
		adservice ${2}
	;;

	"currencyservice" )
		currencyservice ${2}
	;;

	"emailservice" )
		emailservice ${2}
	;;

	"paymentservice" )
		paymentservice ${2}
	;;

	"shippingservice" )
		shippingservice ${2}
	;;

	"productcatalogservice" )
		productcatalogservice ${2}
	;;

	"cartservice" )
		cartservice ${2}
	;;

	"recommendationservice" )
		recommendationservice ${2}
	;;

	"frontendservice" )
		frontendservice ${2}
	;;

	"checkoutservice" )
		checkoutservice ${2}
	;;

	* )
		print_usage
		exit 1
esac
