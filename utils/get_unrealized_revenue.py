FEE = 0.08
KILN_SHARE = 0.375

import csv

def main():
    with open('validators.csv', 'r') as file:
        reader = csv.DictReader(file)
        cl_total = 0
        el_total = 0
        for row in reader:
            cl_rewards = int(row['cl_balance'])
            if cl_rewards > 31e18:
                #print(f'CL rewards: {cl_rewards/1e18}')
                exemption = min(cl_rewards, 32e18)
                cl_rewards -= exemption
                print(f'Rewards after correction: {cl_rewards/1e18}')
            
            cl_total += cl_rewards
            
            el_total += int(row['el_balance'])

        print(f'Unclaimed CL rewards: {cl_total/1e18}')
        print(f'Unclaimed EL rewards: {el_total/1e18}')
        total_rewards = cl_total + el_total
        print(f'Total unclaimed rewards: {(total_rewards)/1e18}')
        print(f'Total unrealized revenue: {total_rewards/1e18 * FEE}')
        print(f'Unrealized revenue for Ledger: {total_rewards/1e18*FEE - (total_rewards/1e18 * FEE * KILN_SHARE)}')
        print(f'Unrealized revenue for Kiln: {total_rewards/1e18 * FEE * KILN_SHARE}')

if __name__ == "__main__":
    main()

